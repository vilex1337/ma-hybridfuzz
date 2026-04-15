"""
Attention Distance Computer - Uses LLM attention scores to build a
semantic distance matrix for directed fuzzing. (Gap 1 - Attention Distance-inspired)
"""

import json
import logging
import pickle
from pathlib import Path

import numpy as np

from llm.provider import create_provider

logger = logging.getLogger("pre_phase.attention")


class AttentionComputer:
    def __init__(self, config: dict):
        self.config = config
        self.provider = create_provider(config)
        self.model = self.provider.model
        self.cache_dir = Path(config["paths"]["distance_cache"])
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._matrix = None
        self._functions = None

    def compute(self, source_dir: str, target_function: str):
        """Compute attention-based distance matrix from source code."""
        functions = self._extract_functions(source_dir)
        if not functions:
            logger.warning("No functions extracted from source")
            return

        self._functions = list(functions.keys())
        logger.info("Extracted %d functions, computing attention distances...", len(self._functions))

        # Use LLM to compute semantic relatedness scores between functions
        # This approximates attention-based distance from the paper
        distance_matrix = self._compute_distances(functions, target_function)
        self._matrix = distance_matrix

        # Cache to disk
        cache_data = {
            "functions": self._functions,
            "target": target_function,
            "matrix": distance_matrix.tolist(),
        }
        cache_path = self.cache_dir / "attention_distances.pkl"
        with open(cache_path, "wb") as f:
            pickle.dump(cache_data, f)

        # Also save human-readable version
        readable_path = self.cache_dir / "attention_distances.json"
        with open(readable_path, "w") as f:
            json.dump(
                {
                    "functions": self._functions,
                    "target": target_function,
                    "distances_to_target": {
                        fn: float(distance_matrix[i][self._functions.index(target_function)])
                        for i, fn in enumerate(self._functions)
                        if target_function in self._functions
                    },
                },
                f,
                indent=2,
            )

        logger.info("Distance matrix cached at %s", cache_path)

    def load_cached(self) -> dict:
        """Load pre-computed distance matrix from cache."""
        cache_path = self.cache_dir / "attention_distances.pkl"
        if not cache_path.exists():
            logger.warning("No cached distance matrix found")
            return {}

        with open(cache_path, "rb") as f:
            data = pickle.load(f)

        self._functions = data["functions"]
        self._matrix = np.array(data["matrix"])
        return data

    def get_distance(self, func_name: str, target: str) -> float:
        """Get attention distance between a function and the target."""
        if self._matrix is None or self._functions is None:
            return float("inf")

        try:
            src_idx = self._functions.index(func_name)
            dst_idx = self._functions.index(target)
            return float(self._matrix[src_idx][dst_idx])
        except ValueError:
            return float("inf")

    def get_neighbors(self, target_function: str, top_k: int = 3) -> list[str]:
        """Return the top-k functions closest to *target_function* by attention distance.

        Used by the orchestrator when no complete FCC is available (RANDLUZZ §3.3.3):
        the closest neighbors serve as intermediate reasoning anchors for
        functionality-based seed generation.

        Returns an empty list when no distance matrix has been computed yet.
        """
        if self._matrix is None or self._functions is None:
            logger.warning("get_neighbors called before distance matrix is computed")
            return []

        if target_function not in self._functions:
            logger.warning("Target function '%s' not found in distance matrix", target_function)
            return []

        target_idx = self._functions.index(target_function)
        # Column (or row — matrix is symmetric) of distances to the target
        distances = self._matrix[:, target_idx]

        # Pair each function with its distance, excluding the target itself
        scored = [
            (self._functions[i], float(distances[i]))
            for i in range(len(self._functions))
            if i != target_idx and np.isfinite(distances[i])
        ]
        scored.sort(key=lambda pair: pair[1])

        neighbors = [name for name, _ in scored[:top_k]]
        logger.info(
            "Nearest neighbors for '%s': %s",
            target_function,
            [(n, f"{d:.3f}") for n, d in scored[:top_k]],
        )
        return neighbors

    def _extract_functions(self, source_dir: str) -> dict[str, str]:
        """Extract function names and their bodies from source code."""
        functions = {}
        source_path = Path(source_dir)
        if not source_path.exists():
            return functions

        for ext in ("*.c", "*.cpp", "*.cc"):
            for fpath in source_path.rglob(ext):
                try:
                    content = fpath.read_text(errors="ignore")
                    # Simple function extraction - looks for function definitions
                    funcs = self._parse_functions_from_source(content, str(fpath))
                    functions.update(funcs)
                except Exception as e:
                    logger.debug("Could not parse %s: %s", fpath, e)

        return functions

    def _parse_functions_from_source(self, content: str, filepath: str) -> dict[str, str]:
        """Basic C/C++ function extraction using heuristics."""
        functions = {}
        lines = content.split("\n")
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            # Look for function definitions (simplified heuristic)
            if (
                "(" in line
                and ")" in line
                and "{" in line
                and not line.startswith("//")
                and not line.startswith("#")
                and not line.startswith("if")
                and not line.startswith("while")
                and not line.startswith("for")
                and not line.startswith("switch")
            ):
                # Extract function name
                before_paren = line.split("(")[0].strip()
                parts = before_paren.split()
                if parts:
                    func_name = parts[-1].lstrip("*&")
                    if func_name and func_name.isidentifier():
                        # Collect function body
                        brace_count = line.count("{") - line.count("}")
                        body_lines = [lines[i]]
                        j = i + 1
                        while j < len(lines) and brace_count > 0:
                            body_lines.append(lines[j])
                            brace_count += lines[j].count("{") - lines[j].count("}")
                            j += 1
                        body = "\n".join(body_lines)
                        if len(body) < 5000:
                            functions[func_name] = body
                        i = j
                        continue
            i += 1
        return functions

    def _compute_distances(self, functions: dict[str, str], target: str) -> np.ndarray:
        """Use LLM to compute semantic distances between functions."""
        func_names = list(functions.keys())
        n = len(func_names)
        matrix = np.full((n, n), float("inf"))
        np.fill_diagonal(matrix, 0.0)

        # Batch functions for LLM analysis
        # Send function summaries and ask LLM to rate relatedness
        func_summaries = {}
        for name, body in functions.items():
            # Keep first 500 chars of each function
            func_summaries[name] = body[:500]

        # Process in chunks to stay within token limits
        chunk_size = 20
        for start in range(0, n, chunk_size):
            end = min(start + chunk_size, n)
            chunk_names = func_names[start:end]
            chunk_bodies = {name: func_summaries[name] for name in chunk_names}

            prompt = f"""Analyze the semantic relatedness of these C/C++ functions to the target function "{target}".

Functions:
{json.dumps(chunk_bodies, indent=2)[:8000]}

For each function, rate its semantic distance to "{target}" on a scale of 0.0 to 1.0:
- 0.0 = the function itself or direct caller
- 0.1-0.3 = closely related (direct data flow, shared variables)
- 0.3-0.6 = moderately related (same module, indirect connection)
- 0.6-0.9 = loosely related (same program, different subsystem)
- 1.0 = unrelated

Return a JSON object mapping function_name -> distance_score.
Return ONLY valid JSON."""

            text = self.provider.generate(
                prompt=prompt,
                max_tokens=2048,
                temperature=0.1,
            )

            distances = self._parse_distances(text)

            target_idx = func_names.index(target) if target in func_names else -1
            for name, dist in distances.items():
                if name in func_names and target_idx >= 0:
                    src_idx = func_names.index(name)
                    matrix[src_idx][target_idx] = dist
                    matrix[target_idx][src_idx] = dist

        return matrix

    def _parse_distances(self, text: str) -> dict[str, float]:
        try:
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0]
            elif "```" in text:
                text = text.split("```")[1].split("```")[0]
            data = json.loads(text.strip())
            return {k: float(v) for k, v in data.items()}
        except (json.JSONDecodeError, ValueError) as e:
            logger.error("Failed to parse distances: %s", e)
            return {}
