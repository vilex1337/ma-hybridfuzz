"""
Coverage Checker — LLVM source-based function coverage for the RANDLUZZ pre-phase.

RANDLUZZ §3.3.2: "By analyzing the instrumentation execution logs, we can
determine whether these inputs reach the neighboring function."

The "instrumentation execution logs" are produced by compiling a separate
coverage-instrumented binary alongside the AFL++ fuzzing binary.  This is
the standard AFL++ ecosystem approach for function-level coverage measurement
(used by afl-cov, LibFuzzer coverage reports, and academic directed fuzzers
such as DAFL and SelectFuzz):

    1. Compile a coverage binary with LLVM's source-based instrumentation:
           clang -fprofile-instr-generate -fcoverage-mapping -g -o <cov_bin> src/
    2. Run the seed through the coverage binary:
           LLVM_PROFILE_FILE=/tmp/run.profraw <cov_bin> <seed_file>
    3. Merge profile data and export function coverage:
           llvm-profdata merge -sparse run.profraw -o run.profdata
           llvm-cov export <cov_bin> --instr-profile=run.profdata --format=text

This gives exact function-level hit counts.  AFL++ edge bitmap is NOT used
here because edges alone cannot identify function entries reliably without a
compile-time edge-to-function mapping (which AFL_LLVM_DOCUMENT_IDS is meant
to provide, but is unavailable in this build of AFL++).

Why a separate binary:
- The AFL++ fuzzing binary uses XOR-hashed edge IDs (non-reversible to PCs).
- LLVM PCGUARD + pc-table can be combined with afl-clang-fast but produces
  misaligned guard ID ranges at runtime due to AFL++ runtime guards.
- A dedicated -fprofile-instr-generate binary avoids all of these conflicts.

Usage::

    checker = CoverageChecker(config)
    # checker.build(source_dir, binary_path) called by orchestrator pre-phase
    reached = checker.check_reached_functions(
        binary="/path/to/binary",
        seed_file="/tmp/seed.bin",
        candidate_functions=["main", "parse_input", "process", "vuln_func"],
    )
    # reached == {"main", "parse_input"}
    # → derived_fn = "parse_input" (last hit before first miss in fastest path)
"""

import json
import logging
import os
import subprocess
import tempfile
from pathlib import Path

from config import AppConfig
from logging_utils import VERBOSE_LEVEL

logger = logging.getLogger("pre_phase.coverage")

_DEFAULT_TIMEOUT = 10   # seconds per execution


class CoverageChecker:
    """
    Determines which functions from the fastest path were reached at runtime
    by running a seed through an LLVM source-coverage-instrumented binary.
    """

    def __init__(self, config: AppConfig):
        self.config = config
        self._llvm_suffix = self._detect_llvm_suffix()
        self._cov_binary: str | None = config.target.coverage_binary or None
        if self._cov_binary and not Path(self._cov_binary).exists():
            logger.warning(
                "[Coverage] Configured coverage_binary not found: %s", self._cov_binary
            )
            self._cov_binary = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def build(self, source_dir: str, reference_binary: str) -> bool:
        """
        Compile a coverage-instrumented binary from *source_dir*.

        The output binary is placed alongside the reference binary with the
        suffix ``_covbuild``.  Subsequent calls to ``check_reached_functions``
        will use it automatically.

        Returns True on success, False on failure (coverage check will fall
        back to the conservative heuristic in that case).
        """
        if self._cov_binary and Path(self._cov_binary).exists():
            logger.info(
                "[Coverage] Coverage binary already exists: %s", self._cov_binary
            )
            return True

        reference_binary_path = Path(reference_binary)
        out_binary_base = (
            reference_binary_path.with_suffix("")
            if reference_binary_path.suffix
            else reference_binary_path
        )
        out_binary = str(out_binary_base) + "_covbuild"
        binary_name = reference_binary_path.stem
        logger.log(
            VERBOSE_LEVEL,
            "[Coverage] Build plan: source_dir=%s reference=%s output=%s binary_name=%s llvm_suffix=%s",
            source_dir,
            reference_binary,
            out_binary,
            binary_name,
            self._llvm_suffix or "<default>",
        )
        success = self._compile_coverage_binary(source_dir, out_binary, binary_name)
        if success:
            self._cov_binary = out_binary
        return success

    def check_reached_functions(
        self,
        binary: str,
        seed_file: str,
        candidate_functions: list[str],
        timeout: float = _DEFAULT_TIMEOUT,
    ) -> set[str]:
        """
        Return the subset of *candidate_functions* actually reached when
        *binary*'s coverage counterpart is executed with *seed_file*.

        Args:
            binary              : path to the (AFL++ instrumented) target binary.
                                  Used to locate the companion coverage binary.
            seed_file           : path to the seed input file.
            candidate_functions : ordered list of function names from fastest path.
            timeout             : max execution seconds.

        Returns:
            Set of function names that were hit.
            Falls back to ``{candidate_functions[0]}`` on any failure.
        """
        if not candidate_functions:
            return set()
        logger.log(
            VERBOSE_LEVEL,
            "[Coverage] Checking runtime reachability: binary=%s seed=%s candidates=%d",
            binary,
            seed_file,
            len(candidate_functions),
        )

        fallback: set[str] = {candidate_functions[0]}

        # Locate coverage binary
        cov_bin = self._resolve_cov_binary(binary)
        if cov_bin is None:
            logger.warning(
                "[Coverage] No coverage binary found for %s — "
                "using fallback (entry only). "
                "Run coverage_checker.build(source_dir, binary) to enable "
                "runtime coverage checking.",
                binary,
            )
            return fallback

        # Execute seed through coverage binary
        profraw = self._run_profraw(cov_bin, seed_file, timeout)
        if profraw is None:
            logger.warning("[Coverage] Coverage run failed — using fallback")
            return fallback

        # Parse function coverage
        try:
            reached = self._parse_coverage(cov_bin, profraw, set(candidate_functions))
        finally:
            Path(profraw).unlink(missing_ok=True)

        if not reached:
            logger.warning(
                "[Coverage] llvm-cov returned no hits in candidates — "
                "using fallback (entry only)"
            )
            return fallback

        logger.info(
            "[Coverage] Runtime hit in fastest path: %s",
            " -> ".join(f for f in candidate_functions if f in reached),
        )
        return reached

    # ------------------------------------------------------------------
    # Coverage binary compilation
    # ------------------------------------------------------------------

    def _compile_coverage_binary(self, source_dir: str, out_binary: str, binary_name: str) -> bool:
        from pre_phase.binary_builder import build_binary

        cc = self._find_clang()
        if cc is None:
            logger.error("[Coverage] clang not found in PATH")
            return False

        # Derive clang++ from clang (e.g. clang-14 → clang++-14)
        cxx = cc.replace("clang", "clang++", 1)

        extra_cflags = [
            "-fprofile-instr-generate",
            "-fcoverage-mapping",
            "-g",
            "-O0",
            *self.config.target.coverage_compile_flags,
        ]

        logger.info("[Coverage] Compiling coverage binary: %s", out_binary)
        logger.log(
            VERBOSE_LEVEL,
            "[Coverage] Coverage compile settings: cc=%s cxx=%s flags=%s",
            cc,
            cxx,
            extra_cflags,
        )
        return build_binary(source_dir, out_binary, cc, cxx, binary_name, extra_cflags=extra_cflags)

    # ------------------------------------------------------------------
    # Profile execution + parsing
    # ------------------------------------------------------------------

    def _run_profraw(
        self, cov_binary: str, seed_file: str, timeout: float
    ) -> str | None:
        """
        Execute *cov_binary* with *seed_file* as input and return the path
        to the raw profile file, or None on failure.

        Input delivery is controlled by ``target.args`` in config (AFL++ ``@@``
        convention):
        - If ``@@`` appears in ``target.args``, the seed path replaces ``@@``
          in the argv list and stdin is left closed.
        - Otherwise the seed is piped to the binary's stdin (the binary is
          invoked with no extra arguments).
        """
        with tempfile.NamedTemporaryFile(suffix=".profraw", delete=False) as tmp:
            profraw = tmp.name

        env = {**os.environ, "LLVM_PROFILE_FILE": profraw}
        seed_path = str(Path(seed_file).resolve())

        # Build command and determine stdin source from config args.
        raw_args: list[str] = self.config.target.args
        if "@@" in raw_args:
            cmd = [cov_binary] + [seed_path if a == "@@" else a for a in raw_args]
            stdin_src = None
        else:
            cmd = [cov_binary] + raw_args
            stdin_src = seed_path
        logger.log(
            VERBOSE_LEVEL,
            "[Coverage] Executing coverage probe: cmd=%s stdin=%s profraw=%s timeout=%.1fs",
            " ".join(cmd),
            stdin_src or "<none>",
            profraw,
            timeout,
        )

        try:
            if stdin_src is not None:
                with open(stdin_src, "rb") as seed_fh:
                    subprocess.run(
                        cmd,
                        stdin=seed_fh,
                        capture_output=True,
                        timeout=timeout,
                        env=env,
                    )
            else:
                subprocess.run(
                    cmd,
                    capture_output=True,
                    timeout=timeout,
                    env=env,
                )
            # The profile is written on normal AND crash exit; check it exists.
            if Path(profraw).stat().st_size > 0:
                logger.log(VERBOSE_LEVEL, "[Coverage] Profile captured: %s", profraw)
                return profraw
            logger.warning("[Coverage] profraw file is empty")
            return None
        except subprocess.TimeoutExpired:
            logger.warning("[Coverage] coverage run timed out after %.0fs", timeout)
            return None
        except Exception as exc:
            logger.debug("[Coverage] coverage run error: %s", exc)
            return None

    def _parse_coverage(
        self, cov_binary: str, profraw: str, candidates: set[str]
    ) -> set[str]:
        """
        Merge *profraw* into profdata and run ``llvm-cov export`` to obtain
        per-function hit counts.  Returns the subset of *candidates* with
        count > 0.
        """
        profdata = profraw.replace(".profraw", ".profdata")
        try:
            return self._parse_coverage_inner(cov_binary, profraw, profdata, candidates)
        finally:
            Path(profdata).unlink(missing_ok=True)

    def _parse_coverage_inner(
        self,
        cov_binary: str,
        profraw: str,
        profdata: str,
        candidates: set[str],
    ) -> set[str]:
        merge_bin = self._tool("llvm-profdata")
        cov_bin   = self._tool("llvm-cov")
        logger.log(
            VERBOSE_LEVEL,
            "[Coverage] Parsing coverage: merge_bin=%s cov_bin=%s candidates=%d",
            merge_bin,
            cov_bin,
            len(candidates),
        )

        # llvm-profdata merge
        try:
            r = subprocess.run(
                [merge_bin, "merge", "-sparse", profraw, "-o", profdata],
                capture_output=True, text=True, timeout=30,
            )
        except FileNotFoundError:
            logger.error("[Coverage] llvm-profdata not found: %s", merge_bin)
            return set()
        except subprocess.TimeoutExpired:
            logger.error("[Coverage] llvm-profdata merge timed out")
            return set()
        except OSError as exc:
            logger.error("[Coverage] llvm-profdata OS error: %s", exc)
            return set()
        if r.returncode != 0:
            logger.warning("[Coverage] llvm-profdata failed: %s", r.stderr[:200])
            return set()

        # llvm-cov export
        try:
            r = subprocess.run(
                [cov_bin, "export", cov_binary,
                 f"--instr-profile={profdata}",
                 "--format=text"],
                capture_output=True, text=True, timeout=30,
            )
        except FileNotFoundError:
            logger.error("[Coverage] llvm-cov not found: %s", cov_bin)
            return set()
        except subprocess.TimeoutExpired:
            logger.error("[Coverage] llvm-cov export timed out")
            return set()
        except OSError as exc:
            logger.error("[Coverage] llvm-cov export OS error: %s", exc)
            return set()
        if r.returncode != 0:
            logger.warning("[Coverage] llvm-cov export failed: %s", r.stderr[:200])
            return set()

        reached = self._extract_hit_functions(r.stdout, candidates)
        logger.log(
            VERBOSE_LEVEL,
            "[Coverage] Coverage parse complete: reached=%d/%d",
            len(reached),
            len(candidates),
        )
        return reached

    @staticmethod
    def _extract_hit_functions(json_text: str, candidates: set[str]) -> set[str]:
        """
        Parse ``llvm-cov export --format=text`` JSON and return function names
        from *candidates* whose execution count > 0.

        The JSON schema is::

            {
              "data": [{
                "functions": [
                  {"name": "func_a", "count": 1, ...},
                  ...
                ]
              }]
            }
        """
        reached: set[str] = set()
        try:
            data = json.loads(json_text)
            for record in data.get("data", []):
                for fn in record.get("functions", []):
                    name = fn.get("name", "")
                    count = fn.get("count", 0)
                    if count > 0 and name in candidates:
                        reached.add(name)
        except (json.JSONDecodeError, KeyError) as exc:
            logger.warning("[Coverage] Failed to parse llvm-cov JSON: %s", exc)
        return reached

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _resolve_cov_binary(self, reference_binary: str) -> str | None:
        """
        Return the coverage binary path, checking several candidate locations.
        Priority:
          1. Explicitly configured ``coverage_binary`` in config.
          2. ``<reference_binary>_covbuild`` (built by CoverageChecker.build()).
          3. ``<reference_binary>.cov``.
        """
        if self._cov_binary and Path(self._cov_binary).exists():
            return self._cov_binary

        reference_path = Path(reference_binary)
        base_path = reference_path.parent / reference_path.name

        for suffix in ("_covbuild", ".cov"):
            candidate = str(base_path) + suffix
            if Path(candidate).exists():
                return candidate

        return None

    def _tool(self, base: str) -> str:
        """Return the versioned tool name, e.g. 'llvm-profdata-14'."""
        versioned = f"{base}{self._llvm_suffix}"
        try:
            r = subprocess.run(["which", versioned], capture_output=True, text=True)
            if r.returncode == 0:
                return versioned
        except OSError as exc:
            logger.debug("[Coverage] 'which %s' failed: %s", versioned, exc)
        return base

    def _find_clang(self) -> str | None:
        """Return the best available clang binary."""
        for name in (f"clang{self._llvm_suffix}", "clang"):
            try:
                r = subprocess.run(["which", name], capture_output=True, text=True)
                if r.returncode == 0:
                    return name
            except OSError as exc:
                logger.debug("[Coverage] 'which %s' failed: %s", name, exc)
        return None

    @staticmethod
    def _detect_llvm_suffix() -> str:
        """
        Detect the LLVM version suffix to prefer versioned tools
        (e.g. ``-14``) over generic ones when both are present.
        """
        for suffix in ("-20", "-19", "-18", "-17", "-16", "-15", "-14", "-13", ""):
            try:
                r = subprocess.run(
                    ["llvm-profdata" + suffix, "--version"],
                    capture_output=True, text=True, timeout=3,
                )
                if r.returncode == 0:
                    return suffix
            except FileNotFoundError:
                continue
        return ""
