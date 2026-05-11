"""
Call Chain Extractor - derives the Function Call Chain (FCC) from entry point
to target function using the Clang AST, as described in the RANDLUZZ paper.

RANDLUZZ §3.2.2 derives the FCC via static analysis of the Clang AST:
  entry (e.g. main / LLVMFuzzerTestOneInput) → ... → target_function

The extractor:
  1. Parses all C/C++ source files via libclang (TranslationUnit.parse).
  2. Walks the AST to build a directed call graph: caller → {callees}.
  3. Runs BFS from each configured entry point to find the shortest path to
     the target function.

If libclang is unavailable or no path is found the extractor returns an empty
list, which causes the orchestrator to fall back to the config-supplied FCC
(or functionality-based reasoning if that is also empty).
"""

import json
import logging
from collections import deque
from pathlib import Path
from typing import Any

logger = logging.getLogger("pre_phase.call_chain")

# cindex is typed as Any so that attribute access compiles regardless of
# whether libclang is installed.  All code paths that use it are guarded by
# the _CLANG_AVAILABLE flag checked at the start of extract().
cindex: Any = None
_CLANG_AVAILABLE = False
try:
    import clang.cindex as cindex  # provided by the `libclang` PyPI package  # type: ignore[import-untyped]

    _CLANG_AVAILABLE = True
except ImportError:
    logger.warning(
        "libclang Python bindings not found (pip install libclang). "
        "Call chain extraction will be skipped."
    )


class CallChainExtractor:
    """
    Extracts the shortest call chain from an entry point to a target function
    by walking the Clang AST of the project's source files.

    Usage::

        extractor = CallChainExtractor(config)
        chain = extractor.extract(
            source_dir="/path/to/src",
            target_function="vulnerable_func",
        )
        # chain == ["main", "parse_input", "process_chunk", "vulnerable_func"]
    """

    # Default entry-point names tried in order.  LLVMFuzzerTestOneInput is the
    # standard libFuzzer harness; main covers standalone programs.
    DEFAULT_ENTRY_POINTS = ["main", "LLVMFuzzerTestOneInput"]

    def __init__(self, config: dict):
        global _CLANG_AVAILABLE

        self.config = config
        if not _CLANG_AVAILABLE:
            self._index = None
        else:
            try:
                self._index = cindex.Index.create()
            except Exception as exc:
                logger.warning(
                    "libclang could not be initialized (%s). "
                    "Call chain extraction will be skipped.",
                    exc,
                )
                _CLANG_AVAILABLE = False
                self._index = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def extract(
        self,
        source_dir: str,
        target_function: str,
        entry_points: list[str] | None = None,
        compile_commands_dir: str | None = None,
    ) -> list[str]:
        """
        Return the shortest call chain ``[entry, ..., target_function]``.

        Args:
            source_dir          : root directory that contains the C/C++ sources.
            target_function     : the vulnerable function to reach.
            entry_points        : callers to start BFS from.  Defaults to
                                  ``["main", "LLVMFuzzerTestOneInput"]``.
            compile_commands_dir: directory that contains ``compile_commands.json``
                                  (optional; improves parse accuracy by supplying
                                  the real compiler flags for each TU).

        Returns:
            List of function names forming the chain, or ``[]`` when no path
            is found or when libclang is unavailable.
        """
        if not _CLANG_AVAILABLE:
            logger.info("[CallChain] libclang unavailable — skipping AST extraction.")
            return []

        if entry_points is None:
            entry_points = list(self.DEFAULT_ENTRY_POINTS)

        # Allow config to supply extra entry-point names.
        cfg_entries = self.config.get("target", {}).get("entry_points", [])
        for ep in cfg_entries:
            if ep not in entry_points:
                entry_points.append(ep)

        logger.info(
            "[CallChain] Building call graph for source_dir=%s target=%s",
            source_dir,
            target_function,
        )

        compile_cmds = self._load_compile_commands(source_dir, compile_commands_dir)
        call_graph = self._build_call_graph(source_dir, compile_cmds)

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

    # ------------------------------------------------------------------
    # Call graph construction
    # ------------------------------------------------------------------

    def _build_call_graph(
        self,
        source_dir: str,
        compile_cmds: dict[str, list[str]],
    ) -> dict[str, set[str]]:
        """
        Walk all C/C++ source files under ``source_dir`` and build a directed
        call graph: ``{caller_name: {callee_name, ...}}``.
        """
        call_graph: dict[str, set[str]] = {}
        source_path = Path(source_dir)
        if not source_path.exists():
            logger.warning("[CallChain] source_dir does not exist: %s", source_dir)
            return call_graph

        extensions = ("*.c", "*.cpp", "*.cc", "*.cxx")
        parsed_count = 0
        for ext in extensions:
            for fpath in source_path.rglob(ext):
                try:
                    self._parse_translation_unit(str(fpath), call_graph, compile_cmds)
                    parsed_count += 1
                except Exception as exc:  # noqa: BLE001
                    logger.debug("[CallChain] Could not parse %s: %s", fpath, exc)

        logger.debug("[CallChain] Parsed %d translation units", parsed_count)
        return call_graph

    def _parse_translation_unit(
        self,
        filepath: str,
        call_graph: dict[str, set[str]],
        compile_cmds: dict[str, list[str]],
    ) -> None:
        """Parse a single source file and update *call_graph* in-place."""
        args = compile_cmds.get(filepath) or compile_cmds.get(Path(filepath).name, [])
        if not args:
            suffix = Path(filepath).suffix.lower()
            lang = "c++" if suffix in (".cpp", ".cc", ".cxx") else "c"
            args = [f"-x{lang}", "-std=gnu11" if lang == "c" else "-std=gnu++17"]

        if self._index is None:
            return
        tu = self._index.parse(filepath, args=args)
        if tu is None:
            return

        self._walk_cursor(tu.cursor, call_graph, current_func=None)

    def _walk_cursor(
        self,
        cursor: Any,
        call_graph: dict[str, set[str]],
        current_func: str | None,
    ) -> None:
        """
        Recursively walk the AST cursor, updating *call_graph*.

        ``current_func`` is the name of the enclosing function definition.
        It propagates down the child list so that every CALL_EXPR is
        attributed to its containing function.
        """
        kind = cursor.kind

        # Enter a new function definition — this becomes the owning scope for
        # its subtree.  C does not allow nested definitions, so this is safe.
        if kind in (
            cindex.CursorKind.FUNCTION_DECL,
            cindex.CursorKind.CXX_METHOD,
            cindex.CursorKind.FUNCTION_TEMPLATE,
            cindex.CursorKind.CONSTRUCTOR,
            cindex.CursorKind.DESTRUCTOR,
        ) and cursor.is_definition():
            func_name = str(cursor.spelling or "")
            if func_name:
                current_func = func_name
                call_graph.setdefault(func_name, set())

        # Record a direct call edge.
        elif kind == cindex.CursorKind.CALL_EXPR and current_func is not None:
            callee = cursor.spelling
            # For indirect calls (function pointers), spelling is often empty
            # or refers to the pointer variable — skip those.
            if callee and callee != current_func:
                call_graph.setdefault(current_func, set()).add(callee)

        for child in cursor.get_children():
            self._walk_cursor(child, call_graph, current_func)

    # ------------------------------------------------------------------
    # Shortest-path search
    # ------------------------------------------------------------------

    @staticmethod
    def _bfs_shortest_path(
        call_graph: dict[str, set[str]],
        entry_points: list[str],
        target: str,
    ) -> list[str]:
        """
        BFS over the call graph to find the shortest call chain from any of the
        ``entry_points`` to ``target``.

        Returns the chain ``[entry, ..., target]`` or ``[]`` if unreachable.
        All entry points are tried; the globally shortest result is returned.
        """
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

                # Prune paths already longer than the current best.
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

    # ------------------------------------------------------------------
    # compile_commands.json helpers
    # ------------------------------------------------------------------

    def _load_compile_commands(
        self,
        source_dir: str,
        compile_commands_dir: str | None,
    ) -> dict[str, list[str]]:
        """
        Load compiler flags from ``compile_commands.json`` if available.

        Returns a dict mapping ``filepath -> [compiler_flags]``.
        Falls back to ``{}`` when the file is not found or cannot be parsed.
        """
        search_dirs: list[Path] = []
        if compile_commands_dir:
            search_dirs.append(Path(compile_commands_dir))

        src = Path(source_dir)
        for candidate in ("build", "cmake-build-debug", "cmake-build-release", "."):
            search_dirs.append(src / candidate)
            search_dirs.append(src.parent / candidate)

        for d in search_dirs:
            ccjson = d / "compile_commands.json"
            if ccjson.exists():
                try:
                    result = self._parse_compile_commands(ccjson)
                    logger.info("[CallChain] Loaded compile_commands.json from %s", ccjson)
                    return result
                except Exception as exc:  # noqa: BLE001
                    logger.debug("[CallChain] Could not parse %s: %s", ccjson, exc)

        logger.debug(
            "[CallChain] compile_commands.json not found; using default compiler flags."
        )
        return {}

    @staticmethod
    def _parse_compile_commands(path: Path) -> dict[str, list[str]]:
        """
        Parse ``compile_commands.json`` and return ``{source_file: [flags]}``.

        Strips the compiler executable, ``-o <out>``, ``-c``, and the input
        file itself so that libclang can consume the remaining flags directly.
        """
        with path.open() as f:
            entries = json.load(f)

        result: dict[str, list[str]] = {}
        for entry in entries:
            src_file = entry.get("file", "")
            if not src_file:
                continue

            raw: list[str] = entry.get("arguments") or entry.get("command", "").split()
            flags: list[str] = []
            skip_next = False
            for i, token in enumerate(raw):
                if skip_next:
                    skip_next = False
                    continue
                if i == 0:
                    continue  # compiler executable
                if token in ("-o", "-MF"):
                    skip_next = True
                    continue
                if token == "-c" or token == src_file:
                    continue
                flags.append(token)

            result[src_file] = flags
            result[Path(src_file).name] = flags  # also index by basename

        return result

    # ------------------------------------------------------------------
    # Debug utility
    # ------------------------------------------------------------------

    def dump_call_graph(self, source_dir: str, output_path: str) -> None:
        """Write the call graph as JSON to *output_path* for debugging."""
        if not _CLANG_AVAILABLE:
            logger.warning("[CallChain] libclang unavailable — cannot dump call graph.")
            return
        compile_cmds = self._load_compile_commands(source_dir, None)
        call_graph = self._build_call_graph(source_dir, compile_cmds)
        serialisable = {k: sorted(v) for k, v in call_graph.items()}
        with open(output_path, "w") as f:
            json.dump(serialisable, f, indent=2)
        logger.info("[CallChain] Call graph written to %s", output_path)
