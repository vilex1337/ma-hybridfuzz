"""
MA-HybridFuzz Orchestrator
Coordinates the full pipeline: Pre-phase -> Fuzzing Loop -> On-demand Reassessment
"""

import argparse
import logging
import signal
import time
from pathlib import Path

import yaml

from pre_phase.reasoning_agent import ReasoningAgent
from pre_phase.reassessment_agent import ReassessmentAgent
from pre_phase.persistent_memory import PersistentMemory
from pre_phase.seed_generator import SeedGenerator
from pre_phase.mutator_generator import MutatorGenerator
from pre_phase.attention_computer import AttentionComputer
from pre_phase.call_chain_extractor import CallChainExtractor
from pre_phase.coverage_checker import CoverageChecker
from fuzzing.afl_runner import AFLRunner
from fuzzing.scheduler import AttentionScheduler

# Console-only handler at module level; a file handler is added in
# Orchestrator.__init__ once the config (and its log path) is known.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger("orchestrator")


class Orchestrator:
    def __init__(self, config_path: str):
        with open(config_path) as f:
            self.config = yaml.safe_load(f)

        # Add file handler now that the config log path is available.
        log_dir = Path(self.config["paths"]["logs"])
        log_dir.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_dir / "orchestrator.log")
        file_handler.setFormatter(
            logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s")
        )
        logging.getLogger().addHandler(file_handler)

        self.reasoning = ReasoningAgent(self.config)
        self.reassessment = ReassessmentAgent(self.config)
        self.memory = PersistentMemory(self.config)
        self.seed_gen = SeedGenerator(self.config)
        self.mutator_gen = MutatorGenerator(self.config)
        self.attention = AttentionComputer(self.config)
        self.call_chain = CallChainExtractor(self.config)
        self.coverage_checker = CoverageChecker(self.config)
        self.afl = AFLRunner(self.config)
        self.scheduler = AttentionScheduler(self.config)

        # Pre-phase context preserved for reassessment (avoids re-querying LLM)
        self._pre_phase_ctx: dict = {}

        self._running = True
        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)

    def _handle_signal(self, signum, _frame):
        logger.info("Received signal %d, shutting down...", signum)
        self._running = False

    def run(self):
        logger.info("=== MA-HybridFuzz Starting ===")
        logger.info("Target: %s", self.config["target"]["binary"])
        logger.info("Target function: %s", self.config["target"]["target_function"])

        # Phase 1: Pre-phase (Gap 3 - LLM-based)
        logger.info("--- Phase 1: Pre-phase (LLM) ---")
        self._run_pre_phase()

        # Phase 2: Fuzzing loop (Gap 1 - Native speed)
        logger.info("--- Phase 2: Fuzzing Loop ---")
        self._run_fuzzing_loop()

        logger.info("=== MA-HybridFuzz Complete ===")
        self._report_results()

    def _run_pre_phase(self):
        target_function = self.config["target"]["target_function"]
        source_dir = self.config["target"]["source_dir"]
        bug_report = self.config["target"].get("bug_report", "")
        program_usage = self.config["target"].get("program_usage", "")
        bug_type = self.config["target"]["bug_type"]

        # ── FCC: Function Call Chain ──────────────────────────────────────────
        # Resolution order (first match wins):
        #   1. Explicit list in config  → user override, always respected.
        #   2. Persistent memory cache  → skip re-extraction on restart.
        #   3. Clang AST extraction     → static analysis, result is cached.
        #   4. Empty list               → fall back to functionality-based mode.
        fcc: list[str] = self.config["target"].get("fcc", [])

        if fcc:
            logger.info(
                "[Pre-phase FCC] Using config-supplied FCC (%d hops): %s",
                len(fcc) - 1,
                " -> ".join(fcc),
            )
        else:
            # Try persistent memory before running the (potentially slow) AST walk.
            cached_fcc = self.memory.load_fcc(target_function, bug_type)
            if cached_fcc is not None:
                fcc = cached_fcc
                logger.info(
                    "[Pre-phase FCC] Restored FCC from persistent memory (%d hops): %s",
                    len(fcc) - 1,
                    " -> ".join(fcc),
                )
            else:
                compile_commands_dir = self.config["target"].get("compile_commands_dir")
                logger.info(
                    "[Pre-phase FCC] No cached FCC — extracting from Clang AST "
                    "(source_dir=%s, target=%s)...",
                    source_dir,
                    target_function,
                )
                fcc = self.call_chain.extract(
                    source_dir=source_dir,
                    target_function=target_function,
                    compile_commands_dir=compile_commands_dir,
                )
                if fcc:
                    logger.info(
                        "[Pre-phase FCC] Extracted call chain (%d hops): %s",
                        len(fcc) - 1,
                        " -> ".join(fcc),
                    )
                    self.memory.save_fcc(target_function, bug_type, fcc)
                else:
                    logger.warning(
                        "[Pre-phase FCC] Could not extract call chain; "
                        "reasoning will fall back to functionality-based mode."
                    )

        # ── SA: Static Analysis ───────────────────────────────────────────────
        # Compute attention distance matrix (uses Clang-AST-derived call graph)
        logger.info("[Pre-phase SA] Computing attention distance matrix...")
        self.attention.compute(source_dir=source_dir, target_function=target_function)
        logger.info("[Pre-phase SA] Attention distance matrix cached")

        # ── Coverage Binary ───────────────────────────────────────────────────
        # Build the LLVM source-coverage binary used by CoverageChecker to
        # determine which functions a seed reaches at runtime (RANDLUZZ §3.3.2).
        # This is separate from the AFL++ fuzzing binary.
        binary = self.config["target"].get("binary", "")
        logger.info("[Pre-phase Coverage] Building coverage-instrumented binary...")
        cov_ok = self.coverage_checker.build(
            source_dir=source_dir,
            reference_binary=binary,
        )
        if cov_ok:
            logger.info("[Pre-phase Coverage] Coverage binary ready")
        else:
            logger.warning(
                "[Pre-phase Coverage] Coverage binary build failed — "
                "seed reasoning will use conservative fallback (entry only)"
            )

        def _configured_corpus_dir():
            candidate_paths = []
            for section_name in ("fuzzing", "afl", "aflpp"):
                section = self.config.get(section_name, {})
                if not isinstance(section, dict):
                    continue
                for key in ("corpus_dir", "input_dir", "seed_dir"):
                    value = section.get(key)
                    if value:
                        candidate_paths.append(value)

            for path_str in candidate_paths:
                corpus_dir = Path(path_str)
                if corpus_dir.exists():
                    return corpus_dir

            if candidate_paths:
                return Path(candidate_paths[0])
            return None

        def _corpus_has_seed():
            corpus_dir = _configured_corpus_dir()
            if corpus_dir is None or not corpus_dir.exists() or not corpus_dir.is_dir():
                return False
            return any(entry.is_file() for entry in corpus_dir.iterdir())

        # ── Persistent Memory: check for cached pre-phase context ─────────────
        # If the LLM pre-phase was already run for this target, reload from disk
        # and skip all LLM calls (saves ~1-2 API calls per restart).
        cached_ctx = self.memory.load_pre_phase_ctx(target_function, bug_type)
        if cached_ctx is not None:
            if _corpus_has_seed():
                self._pre_phase_ctx = cached_ctx
                logger.info(
                    "[Pre-phase] Restored from persistent memory — skipping LLM pre-phase. "
                    "Memory summary: %s",
                    self.memory.summary(),
                )
                return

            logger.warning(
                "[Pre-phase] Cached context found for %s/%s, but corpus directory is "
                "missing or empty; regenerating pre-phase artifacts.",
                target_function,
                bug_type,
            )

        # ── Bug Information ───────────────────────────────────────────────────
        logger.info("[Pre-phase] Extracting bug information from report...")
        bug_info = self.reasoning.extract_bug_info(bug_report) if bug_report else {}
        logger.info(
            "[Pre-phase] Bug info: function=%s type=%s",
            bug_info.get("function", target_function),
            bug_info.get("vulnerability_type", bug_type),
        )

        # ── Function Summary ──────────────────────────────────────────────────
        # Generate a summary for the target function (and FCC functions if available)
        logger.info("[Pre-phase] Generating function summary for '%s'...", target_function)
        target_src = self._load_function_source(source_dir, target_function)
        target_summary = self.reasoning.summarize_function(
            func_name=target_function,
            func_declaration=target_src.get("declaration", ""),
            func_body=target_src.get("body", ""),
        )
        logger.info(
            "[Pre-phase] Function summary generated: %s...",
            target_summary.get("functionality", "")[:80],
        )

        # Summarize FCC intermediate functions if provided
        fcc_summaries: dict[str, dict] = {target_function: target_summary}
        for func_name in fcc:
            if func_name == target_function:
                continue
            src = self._load_function_source(source_dir, func_name)
            fcc_summaries[func_name] = self.reasoning.summarize_function(
                func_name=func_name,
                func_declaration=src.get("declaration", ""),
                func_body=src.get("body", ""),
            )

        # ── Reachable Seed Generation ─────────────────────────────────────────
        # Step 1: Preliminary seed from Program Usage + Function Summary
        logger.info("[Pre-phase Opt] Generating preliminary seed...")
        prelim = self.reasoning.generate_preliminary_seed(
            target_function=target_function,
            func_summary=target_summary,
            program_usage=program_usage,
        )
        logger.info(
            "[Pre-phase Opt] Preliminary seed: format=%s command=%s",
            prelim.get("input_format", "?"),
            prelim.get("command", "?"),
        )

        # Step 2a: Reasoning along FCC (if complete FCC is available)
        # Step 2b: Reasoning based on Functionality (fallback for incomplete FCC)
        reachable_seeds = self._generate_reachable_seeds(
            preliminary_seed=prelim,
            fcc=fcc,
            fcc_summaries=fcc_summaries,
            target_function=target_function,
            target_summary=target_summary,
            source_dir=source_dir,
            program_usage=program_usage,
        )

        # Materialise all generated seeds to the corpus directory
        logger.info("[Pre-phase Opt] Writing %d reachable seeds to corpus...", len(reachable_seeds))
        written = self.seed_gen.write_seeds(reachable_seeds)
        logger.info("[Pre-phase Opt] Wrote %d seeds", len(written))

        # ── Bug-Specific Mutators ─────────────────────────────────────────────
        logger.info("[Pre-phase Mutator] Generating bug-specific mutators...")
        mutators = self.mutator_gen.generate(
            analysis={
                "bug_info": bug_info,
                "function_summary": target_summary,
                "vulnerability_pattern": bug_info.get("cause", ""),
                "trigger_conditions": bug_info.get("trigger_conditions", []),
            },
            bug_type=bug_info.get("vulnerability_type", self.config["target"]["bug_type"]),
        )
        logger.info("[Pre-phase Mutator] Generated %d custom mutators", len(mutators))

        # ── Persist context for Phase 3 reassessment ──────────────────────────
        # Store everything the reassessment agent needs so we never re-query the
        # LLM for information already gathered in the pre-phase.
        self._pre_phase_ctx = {
            "bug_info": bug_info,
            "target_summary": target_summary,
            "program_usage": program_usage,
            "target_function": target_function,
            "input_format": prelim.get("input_format", "unknown"),
        }
        # Write to disk so a restarted orchestrator can skip the LLM pre-phase.
        self.memory.save_pre_phase_ctx(target_function, bug_type, self._pre_phase_ctx)

    def _generate_reachable_seeds(
        self,
        preliminary_seed: dict,
        fcc: list[str],
        fcc_summaries: dict[str, dict],  # noqa: ARG002 – reserved for future use
        target_function: str,
        target_summary: dict,
        source_dir: str,
        program_usage: str,
    ) -> list[dict]:
        """
        Generate reachable seeds using RANDLUZZ §3.3.2 with runtime-derived
        deviation detection.

        RANDLUZZ §3.3.2 (Figure 6):
          1. Run the preliminary seed → record the execution path.
          2. Compare execution path against the static fastest path (BFS).
          3. The 'derived function' = deepest function in the fastest path
             that was actually reached at runtime.
          4. Make ONE reason_along_fcc call: derived_fn → next_fn_in_path.

        This replaces the old approach that iterated over every static FCC
        hop with a separate LLM call per hop.  Now:
          - The LLM is called ONCE for seed reasoning (derived_fn → goal_fn).
          - The deviation point is determined by RUNTIME coverage, not static.

        Example
        -------
        Fastest path:  A → B → D → E → Target
        Coverage shows A, B, C reached (C is off-path)
        → derived_fn = B  (last hit before first miss in fastest path)
        → goal_fn    = D  (next after B)
        → ONE call:   reason_along_fcc(deviation=B, goal=D)

        Falls back to functionality-based reasoning (§3.3.3) when no fastest
        path is available (e.g. disconnected call graph due to indirect calls).
        """
        seeds = [preliminary_seed]

        if len(fcc) < 2:
            # §3.3.3 – no path found: reason from target's neighbours
            return self._fallback_functionality_seeds(
                target_function=target_function,
                target_summary=target_summary,
                source_dir=source_dir,
                program_usage=program_usage,
                existing_seeds=seeds,
            )

        logger.info(
            "[Pre-phase Opt] Fastest path (%d hops): %s",
            len(fcc) - 1,
            " -> ".join(fcc),
        )

        # ── Step 1: Materialise preliminary seed to a temp file ──────────────
        binary = self.config["target"].get("binary", "")
        temp_seed = self._materialize_seed_temp(preliminary_seed)

        if temp_seed is None:
            logger.warning(
                "[Pre-phase Opt] Cannot materialise preliminary seed — "
                "assuming only entry function was reached"
            )
            reached: set[str] = {fcc[0]}
        else:
            # ── Step 2: Runtime coverage check ──────────────────────────────
            try:
                reached = self.coverage_checker.check_reached_functions(
                    binary=binary,
                    seed_file=str(temp_seed),
                    candidate_functions=fcc,
                )
            finally:
                temp_seed.unlink(missing_ok=True)

        # ── Step 3: Identify derived function ───────────────────────────────
        # Walk fastest path; stop at first function NOT reached at runtime.
        # The last reached function before the gap = derived function.
        derived_fn = self._find_derived_function(fcc, reached)

        if derived_fn is None:
            derived_fn = fcc[0]
            logger.info(
                "[Pre-phase Opt] No path function reached by seed — "
                "starting from entry: %s",
                derived_fn,
            )
        else:
            logger.info(
                "[Pre-phase Opt] Coverage: %s | derived_fn=%s",
                sorted(reached & set(fcc)),
                derived_fn,
            )

        if derived_fn == target_function:
            logger.info(
                "[Pre-phase Opt] Preliminary seed already reaches the target '%s' "
                "— no FCC reasoning needed",
                target_function,
            )
            return seeds

        # ── Step 4: ONE reason_along_fcc LLM call ───────────────────────────
        # Guard: the FCC must end with target_function and derived_fn must not
        # be the last element.  Either condition failing means the FCC is
        # misconfigured or truncated → fall back to functionality-based mode.
        if fcc[-1] != target_function:
            logger.warning(
                "[Pre-phase Opt] FCC does not end with target function '%s' "
                "(last entry is '%s') — falling back to functionality-based mode.",
                target_function,
                fcc[-1],
            )
            return self._fallback_functionality_seeds(
                target_function=target_function,
                target_summary=target_summary,
                source_dir=source_dir,
                program_usage=program_usage,
                existing_seeds=seeds,
            )

        derived_idx = fcc.index(derived_fn)
        if derived_idx + 1 >= len(fcc):
            logger.warning(
                "[Pre-phase Opt] derived_fn '%s' is the last entry in FCC "
                "but target_function check was not triggered — falling back "
                "to functionality-based mode.",
                derived_fn,
            )
            return self._fallback_functionality_seeds(
                target_function=target_function,
                target_summary=target_summary,
                source_dir=source_dir,
                program_usage=program_usage,
                existing_seeds=seeds,
            )

        goal_fn = fcc[derived_idx + 1]

        logger.info(
            "[Pre-phase Opt] Reasoning along FCC: %s → %s (target: %s)",
            derived_fn,
            goal_fn,
            target_function,
        )

        deviation_src = self._load_function_source(source_dir, derived_fn)
        result = self.reasoning.reason_along_fcc(
            current_input_description=(
                f"{preliminary_seed.get('seed_description', 'preliminary seed')} "
                f"(format: {preliminary_seed.get('input_format', 'unknown')})"
            ),
            deviation_function_name=derived_fn,
            deviation_function_body=deviation_src.get("body", ""),
            examined_lines=deviation_src.get("key_lines", []),
            goal_function_name=goal_fn,
            program_usage=program_usage,
        )

        if result.get("seed_content") or result.get("seed_code"):
            seeds.append(self._normalize_seed(result))
            for candidate in result.get("candidate_seeds", []):
                if candidate.get("seed_content") or candidate.get("seed_code"):
                    seeds.append(self._normalize_seed(candidate))

        return seeds

    def _fallback_functionality_seeds(
        self,
        target_function: str,
        target_summary: dict,
        source_dir: str,
        program_usage: str,
        existing_seeds: list[dict],
    ) -> list[dict]:
        """
        §3.3.3 fallback: reason from the target's neighbour functions when
        no fastest path exists (indirect calls, incomplete call graph).
        """
        logger.info(
            "[Pre-phase Opt] No fastest path — reasoning from neighbour functions"
        )
        seeds = list(existing_seeds)
        neighbor_names = self.attention.get_neighbors(target_function, top_k=3)
        for neighbor_name in neighbor_names:
            neighbor_src = self._load_function_source(source_dir, neighbor_name)
            neighbor_summary = self.reasoning.summarize_function(
                func_name=neighbor_name,
                func_declaration=neighbor_src.get("declaration", ""),
                func_body=neighbor_src.get("body", ""),
            )
            result = self.reasoning.reason_based_on_functionality(
                target_function=target_function,
                target_func_summary=target_summary,
                neighbor_function_name=neighbor_name,
                neighbor_func_summary=neighbor_summary,
                program_usage=program_usage,
            )
            if result.get("seed_content") or result.get("seed_code"):
                seeds.append(self._normalize_seed(result))
        return seeds

    @staticmethod
    def _find_derived_function(
        fastest_path: list[str], reached: set[str]
    ) -> str | None:
        """
        Return the deepest function along *fastest_path* that was reached at
        runtime.

        Walk *fastest_path* in order; stop at the first function NOT in
        *reached*.  The last reached function before the gap is the 'derived
        function'.

        Example::

            fastest_path = [A, B, D, E, Target]
            reached      = {A, B, C}   # C is off-path
            → returns B                # D is first miss; B is last hit

        Returns None when nothing in the path was reached.
        """
        derived: str | None = None
        for fn in fastest_path:
            if fn in reached:
                derived = fn
            else:
                break   # first miss in the ordered fastest path
        return derived

    def _materialize_seed_temp(self, seed_dict: dict) -> Path | None:
        """
        Write a seed dict (produced by ReasoningAgent) to a temporary file
        and return its Path.  Returns None on failure; caller must delete.

        Handles both seed_type == "string" (direct content) and
        seed_type == "code" (Python script that generates the file).
        """
        seed_type = seed_dict.get("seed_type", "string")

        if seed_type == "string":
            content = (seed_dict.get("seed_content") or "").encode()
            if not content:
                content = b"\x00"   # minimal non-empty placeholder
            import tempfile
            with tempfile.NamedTemporaryFile(
                suffix="_probe_seed", delete=False
            ) as tmp:
                tmp.write(content)
                return Path(tmp.name)

        if seed_type == "code":
            code = seed_dict.get("seed_code", "")
            if not code:
                return None
            import tempfile
            with tempfile.NamedTemporaryFile(
                suffix="_probe_seed", delete=False
            ) as tmp:
                out_path = Path(tmp.name)
            result = self.seed_gen._run_seed_code(code, out_path)
            return result   # Path or None

        return None

    @staticmethod
    def _normalize_seed(seed: dict) -> dict:
        """
        Normalise a seed dict returned by ReasoningAgent so it matches the
        schema expected by SeedGenerator.write_seeds():

        ReasoningAgent returns         SeedGenerator expects
        ─────────────────────────────  ─────────────────────────────
        description                 -> seed_description
        seed_code present            -> seed_type = "code"
        seed_content present (only)  -> seed_type = "string"
        """
        seed = dict(seed)  # shallow copy – do not mutate the original
        # Map 'description' -> 'seed_description' when the canonical key is absent
        if "seed_description" not in seed and "description" in seed:
            seed["seed_description"] = seed["description"]
        # Infer seed_type when missing
        if "seed_type" not in seed:
            seed["seed_type"] = "code" if seed.get("seed_code") else "string"
        return seed

    def _load_function_source(self, source_dir: str, func_name: str) -> dict:
        """
        Search source files for `func_name` and return its declaration and body.
        Returns empty strings when the function cannot be located.

        Uses a regex to find all occurrences of ``func_name(`` and selects only
        those that are followed by a function body (``{`` after the closing ``)``),
        skipping prototypes (``);``), call sites, and comments.
        """
        import re

        source_path = Path(source_dir)
        if not source_path.exists():
            return {"declaration": "", "body": "", "key_lines": []}

        definition_re = re.compile(r"\b" + re.escape(func_name) + r"\s*\(")

        for ext in ("*.c", "*.cpp", "*.cc"):
            for fpath in source_path.rglob(ext):
                try:
                    content = fpath.read_text(errors="ignore")
                except OSError:
                    continue

                for m in definition_re.finditer(content):
                    # Walk forward through the parameter list using paren balancing
                    # to find the closing ')' of the signature.
                    pos = m.end() - 1  # rewind to the opening '('
                    depth = 0
                    while pos < len(content):
                        ch = content[pos]
                        if ch == "(":
                            depth += 1
                        elif ch == ")":
                            depth -= 1
                            if depth == 0:
                                pos += 1
                                break
                        pos += 1

                    # Check what follows the closing ')' (ignoring whitespace).
                    # A definition opens a '{'; a prototype ends with ';'.
                    lookahead = content[pos:pos + 256].lstrip()
                    if not lookahead.startswith("{"):
                        continue  # prototype, call site, or malformed — skip

                    brace_start = pos + (len(content[pos:pos + 256]) - len(lookahead))

                    # Walk backward from the match start to find the declaration
                    # start, stopping at the previous '}' or ';' so we don't pull
                    # in unrelated code.
                    lookbehind = content[max(0, m.start() - 200):m.start()]
                    last_boundary = max(lookbehind.rfind("}"), lookbehind.rfind(";"))
                    decl_start = (
                        max(0, m.start() - 200) + last_boundary + 1
                        if last_boundary != -1
                        else max(0, m.start() - 200)
                    )
                    declaration = content[decl_start:brace_start].strip()

                    # Extract the body via brace-depth counting from '{'.
                    end = brace_start
                    body_depth = 0
                    found_open = False
                    while end < len(content):
                        ch = content[end]
                        if ch == "{":
                            body_depth += 1
                            found_open = True
                        elif ch == "}" and found_open:
                            body_depth -= 1
                            if body_depth == 0:
                                end += 1
                                break
                        end += 1

                    body = content[brace_start:end].strip()
                    return {
                        "declaration": declaration,
                        "body": body[:4000],
                        "key_lines": [],
                    }

        return {"declaration": "", "body": "", "key_lines": []}

    def _run_fuzzing_loop(self):
        # Instrument target binary
        logger.info("[Fuzzing] Instrumenting target binary...")
        instrumented = self.afl.instrument(
            binary=self.config["target"]["binary"],
            source_dir=self.config["target"]["source_dir"],
            use_asan=self.config["fuzzer"]["use_asan"],
        )

        # Load pre-computed data
        distance_matrix = self.attention.load_cached()
        self.scheduler.set_distance_matrix(distance_matrix)

        # Start AFL++ with custom scheduler and mutators
        logger.info("[Fuzzing] Starting AFL++ with attention-guided scheduling...")
        self.afl.start(
            instrumented_binary=instrumented,
            corpus_dir=self.config["paths"]["corpus"],
            crashes_dir=self.config["paths"]["crashes"],
            mutator_dir=self.config["paths"]["mutators"],
            scheduler=self.scheduler,
        )

        # Monitor loop
        timeout = self.config["fuzzer"]["timeout"]
        plateau_threshold = self.config["reassessment"]["plateau_threshold"]
        max_reassessments = self.config["reassessment"]["max_reassessments"]
        reassessment_count = 0
        last_reassessment_coverage = 0   # coverage at the time of last reassessment
        last_new_coverage_time = time.time()
        last_coverage_count = 0
        start_time = time.time()

        while self._running and (time.time() - start_time) < timeout:
            time.sleep(10)
            stats = self.afl.get_stats()
            if stats is None:
                continue

            current_coverage = stats.get("paths_total", 0)
            crashes = stats.get("unique_crashes", 0)

            if current_coverage > last_coverage_count:
                last_coverage_count = current_coverage
                last_new_coverage_time = time.time()

            elapsed = time.time() - start_time
            logger.info(
                "[Fuzzing] %ds elapsed | coverage: %d | crashes: %d | execs: %s",
                int(elapsed),
                current_coverage,
                crashes,
                stats.get("execs_per_sec", "N/A"),
            )

            # ── Persistent Memory: snapshot coverage every poll cycle ─────────
            self.memory.record_coverage_snapshot(stats)

            # ── Persistent Memory: update confidence for last reassessment ────
            # Once coverage improves after a reassessment, record the delta.
            if reassessment_count > 0 and current_coverage > last_reassessment_coverage:
                self.memory.update_reassessment_confidence(
                    count=reassessment_count,
                    coverage_after=current_coverage,
                )
                last_reassessment_coverage = current_coverage

            # ── Phase 3: On-Demand Reassessment ──────────────────────────────
            plateau_time = time.time() - last_new_coverage_time
            if plateau_time > plateau_threshold and reassessment_count < max_reassessments:
                logger.info(
                    "[Reassessment #%d] Plateau detected (%ds). Activating LLM...",
                    reassessment_count + 1,
                    int(plateau_time),
                )
                self._run_reassessment(stats, reassessment_count + 1, int(plateau_time))
                reassessment_count += 1
                last_reassessment_coverage = current_coverage
                last_new_coverage_time = time.time()

        self.afl.stop()

    def _run_reassessment(self, afl_stats: dict, reassessment_count: int, plateau_s: int = 0):
        """
        Phase 3: On-Demand Reassessment (Project.md §3).

        Activates at most `max_reassessments` times during the fuzzing session,
        only when a coverage plateau is detected.  Uses exactly 2 LLM calls:
          Call 1 — ReassessmentAgent.diagnose()            → why is fuzzer stuck?
          Call 2 — ReassessmentAgent.generate_recovery_plan() → new seeds + mutators

        All pre-phase context (bug_info, target_summary, program_usage) is reused
        from self._pre_phase_ctx so no additional LLM calls are needed for context.
        New seeds are hot-added to the corpus directory; AFL++ picks them up
        automatically via its dynamic queue refresh.

        Args:
            afl_stats         : current AFL++ stats dict
            reassessment_count: 1-based index of this reassessment
            plateau_s         : actual seconds without new coverage (measured by caller)
        """
        ctx = self._pre_phase_ctx
        if not ctx:
            logger.warning("[Reassessment] No pre-phase context available, skipping.")
            return

        corpus_dir = self.config["paths"]["corpus"]
        crashes_dir = self.config["paths"]["crashes"]

        # ── Build runtime summaries (no LLM) ─────────────────────────────────
        corpus_summary = ReassessmentAgent.summarize_corpus(corpus_dir)
        crash_summary = ReassessmentAgent.summarize_crashes(crashes_dir)
        coverage_before = int(afl_stats.get("paths_total", 0))

        target_info = {
            "target_function": ctx.get("target_function", ""),
            "bug_type": ctx.get("bug_info", {}).get("vulnerability_type",
                         self.config["target"]["bug_type"]),
            "input_format": ctx.get("input_format", "unknown"),
        }

        # ── Persistent Memory: load history to avoid repeating failures ───────
        failed_strategies = self.memory.get_failed_strategies()
        coverage_trend = self.memory.get_coverage_trend(last_n=10)
        if failed_strategies:
            logger.info(
                "[Reassessment #%d] %d previously failed strategies loaded from memory.",
                reassessment_count, len(failed_strategies),
            )

        # ── Call 1: Diagnose ──────────────────────────────────────────────────
        diagnosis = self.reassessment.diagnose(
            afl_stats=afl_stats,
            corpus_summary=corpus_summary,
            crash_summary=crash_summary,
            stuck_duration_s=plateau_s,
            target_info=target_info,
            bug_info=ctx.get("bug_info", {}),
        )

        # ── Call 2: Recovery plan (with persistent memory context) ────────────
        plan = self.reassessment.generate_recovery_plan(
            diagnosis=diagnosis,
            target_summary=ctx.get("target_summary", {}),
            program_usage=ctx.get("program_usage", ""),
            bug_info=ctx.get("bug_info", {}),
            reassessment_count=reassessment_count,
            failed_strategies=failed_strategies,
            coverage_trend=coverage_trend,
        )

        # ── Apply: write new seeds ────────────────────────────────────────────
        new_seeds = plan.get("new_seeds", [])
        written: list = []
        if new_seeds:
            written = self.seed_gen.write_seeds(new_seeds)
            logger.info("[Reassessment #%d] Added %d new seeds to corpus", reassessment_count, len(written))
        else:
            logger.warning("[Reassessment #%d] Recovery plan produced no seeds", reassessment_count)

        # ── Apply: regenerate mutators if strategies changed ──────────────────
        mutator_update = plan.get("mutator_update", {})
        if mutator_update and plan.get("mutation_strategies"):
            new_mutators = self.mutator_gen.generate(
                analysis=mutator_update,
                bug_type=target_info["bug_type"],
            )
            logger.info(
                "[Reassessment #%d] Generated %d updated mutators (focus: %s)",
                reassessment_count,
                len(new_mutators),
                plan.get("mutator_focus", "")[:60],
            )

        # ── Persistent Memory: record this reassessment ───────────────────────
        self.memory.record_reassessment(
            count=reassessment_count,
            diagnosis=diagnosis,
            plan=plan,
            seeds_written=len(written),
            coverage_before=coverage_before,
        )

        logger.info(
            "[Reassessment #%d] Complete. Rationale: %s",
            reassessment_count,
            plan.get("rationale", "")[:120],
        )

    def _report_results(self):
        crashes_dir = Path(self.config["paths"]["crashes"])
        # AFL++ writes crashes under <out>/default/crashes/id:* (when launched
        # with default fuzzer ID) or <out>/<name>/crashes/id:* for named runs.
        # Fall back to a recursive glob so we count crashes regardless of layout.
        crash_files = (
            list(crashes_dir.rglob("crashes/id:*")) if crashes_dir.exists() else []
        )
        logger.info("=== Results ===")
        logger.info("Total crashes found: %d", len(crash_files))
        if crash_files:
            for f in crash_files[:10]:
                logger.info("  - %s", f.relative_to(crashes_dir))
            if len(crash_files) > 10:
                logger.info("  ... and %d more", len(crash_files) - 10)
        logger.info("Crashes directory: %s", crashes_dir)
        logger.info("Logs: %s", self.config["paths"]["logs"])


def main():
    parser = argparse.ArgumentParser(description="MA-HybridFuzz Orchestrator")
    parser.add_argument(
        "-c", "--config",
        default="/opt/mahybridfuzz/configs/default.yml",
        help="Path to config file",
    )
    args = parser.parse_args()

    orchestrator = Orchestrator(args.config)
    orchestrator.run()


if __name__ == "__main__":
    main()
