"""
Call Chain Extractor - derives the Function Call Chain (FCC) from entry point
to target function using LLVM IR (via CFGExtractor).

Replaces the previous libclang AST-based approach, which had three failure modes
with C++ class methods:
  1. Inline method bodies not expanded (COMPOUND_STMT empty without full compile flags)
  2. Member calls through objects produce CALL_EXPR with empty spelling/referenced
  3. Constructor calls recorded as spurious edges

The IR-based approach: CFGExtractor compiles source to LLVM IR with debug info,
demangles function names via !DISubprogram metadata, then this extractor runs
BFS over the resulting call graph.
"""
import logging
from collections import deque

from config import AppConfig
from logging_utils import VERBOSE_LEVEL
from pre_phase.cfg_extractor import CFGExtractor

logger = logging.getLogger("pre_phase.call_chain")


class CallChainExtractor:
    DEFAULT_ENTRY_POINTS = ["main", "LLVMFuzzerTestOneInput"]

    def __init__(self, config: AppConfig):
        self.config = config
        self._extractor = CFGExtractor(config)

    def extract(
        self,
        source_dir: str,
        target_function: str,
        entry_points: list[str] | None = None,
    ) -> list[str]:
        """Return shortest call chain [entry, ..., target_function], or [] if not found."""
        if entry_points is None:
            entry_points = list(self.DEFAULT_ENTRY_POINTS)

        for ep in self.config.target.entry_points:
            if ep not in entry_points:
                entry_points.append(ep)
        logger.log(
            VERBOSE_LEVEL,
            "[CallChain] Entry point candidates: %s",
            entry_points,
        )

        logger.info(
            "[CallChain] Building call graph for source_dir=%s target=%s",
            source_dir,
            target_function,
        )

        call_graph = self._extractor.build_call_graph(source_dir)
        if not call_graph:
            logger.warning("[CallChain] IR compilation failed; call graph is empty.")

        logger.info(
            "[CallChain] Call graph built: %d functions, %d call edges",
            len(call_graph),
            sum(len(v) for v in call_graph.values()),
        )

        chain = self._bfs_shortest_path(call_graph, entry_points, target_function)

        if chain:
            logger.info("[CallChain] Extracted FCC: %s", " -> ".join(chain))
        else:
            logger.warning(
                "[CallChain] No path found from %s to '%s'. "
                "Will fall back to config FCC or functionality-based reasoning.",
                entry_points,
                target_function,
            )

        return chain

    @staticmethod
    def _bfs_shortest_path(
        call_graph: dict[str, set[str]],
        entry_points: list[str],
        target: str,
    ) -> list[str]:
        """BFS over the call graph; returns the globally shortest chain."""
        best: list[str] = []

        for entry in entry_points:
            if entry == target:
                return [target]
            if entry not in call_graph:
                continue

            visited: set[str] = {entry}
            queue: deque[list[str]] = deque([[entry]])

            while queue:
                path = queue.popleft()

                if best and len(path) >= len(best):
                    continue

                node = path[-1]
                for callee in call_graph.get(node, ()):
                    if callee == target:
                        candidate = path + [callee]
                        if not best or len(candidate) < len(best):
                            best = candidate
                        break
                    if callee not in visited:
                        visited.add(callee)
                        queue.append(path + [callee])

        return best
