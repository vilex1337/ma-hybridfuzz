"""
Reassessment Agent - Phase 3: On-Demand LLM Reassessment.

This is MA-HybridFuzz's own contribution beyond RANDLUZZ: an on-demand LLM
agent that activates only when the fuzzer hits a coverage plateau (no new
coverage for N minutes). It uses at most 2 LLM calls per activation to stay
within the project budget of 3-4 total LLM calls per target (Project.md).

Design (Project.md §3, ARCHITECTURE.md Phase 3):
  - Trigger  : coverage plateau (configurable threshold)
  - Call 1   : diagnose() — why is the fuzzer stuck?
  - Call 2   : generate_recovery_plan() — new seeds + mutation focus

The same 4-part RANDLUZZ query scheme (Task / Attachment / Suggestion /
Answer Template) is reused here for consistency and to leverage the LLM's
structured reasoning capabilities.

Outputs feed directly back into:
  - SeedGenerator.write_seeds()   → new seeds hot-added to AFL++ corpus
  - MutatorGenerator.generate()   → updated bug-specific mutators

The fuzzing loop then continues with no further LLM involvement unless
another plateau is detected (max N reassessments, configurable).
"""

import json
import logging
from pathlib import Path
from pre_phase.base_agent import LLMAgent

logger = logging.getLogger("pre_phase.reassessment")

# Plateau cause categories used in the diagnosis
STUCK_TYPES = [
    "island",           # seed is trapped in a region far from the target
    "format_barrier",   # input format constraint blocking progress
    "path_constraint",  # hard branch condition not satisfied
    "coverage_cliff",   # hitting the same basic blocks repeatedly
    "mutator_bias",     # current mutators not generating useful variants
]


class ReassessmentAgent(LLMAgent):
    """
    On-demand LLM agent for escaping coverage plateaus during directed fuzzing.

    Activated by the orchestrator when no new coverage has been observed for
    `plateau_threshold` seconds. Produces a targeted diagnosis and recovery
    plan in exactly 2 LLM calls, then returns to native-speed fuzzing.

    _build_query, _query_llm, _extract_text, _parse_json inherited from LLMAgent.
    """

    # -------------------------------------------------------------------------
    # Call 1: Diagnose why the fuzzer is stuck
    # -------------------------------------------------------------------------

    def diagnose(
        self,
        afl_stats: dict,
        corpus_summary: dict,
        crash_summary: dict,
        stuck_duration_s: int,
        target_info: dict,
        bug_info: dict,
        best_queue_input: dict | None = None,
        deviation_function_name: str | None = None,
        deviation_function_body: str = "",
        goal_function_name: str | None = None,
        program_usage: str = "",
    ) -> dict:
        """
        Diagnose why the fuzzer is stuck by reasoning along the FCC.

        Mirrors reason_along_fcc (§3.3.2): given the highest-coverage input that
        AFL++ has found, the deviation function (last FCC step the input reaches),
        and the goal function (next step it fails to reach), the LLM reasons about
        what blocks execution and what the priority gaps are.

        The orchestrator determines deviation_function_name and goal_function_name
        by running the coverage checker on the best queue input — the same mechanism
        used in _generate_reachable_seeds().

        Args:
            afl_stats               : parsed AFL++ fuzzer_stats dict
            corpus_summary          : {count, total_bytes, format_sample, min_size, max_size}
            crash_summary           : {unique_crashes, crash_signatures}
            stuck_duration_s        : seconds since last new coverage was seen
            target_info             : {target_function, bug_type, input_format}
            bug_info                : extracted bug information from pre-phase
            best_queue_input        : highest-coverage AFL++ queue entry — dict with keys:
                                      name, size, hex_preview, text_preview (may be None)
            deviation_function_name : FCC function where the best input last diverges
            deviation_function_body : source code of deviation_function_name (up to 2000 chars)
            goal_function_name      : next FCC function the input fails to reach
            program_usage           : program invocation context

        Returns dict with:
            stuck_type       : one of STUCK_TYPES
            cause            : natural-language explanation
            hypothesis       : what specific change to seeds/mutations could unblock progress
            priority_gaps    : list of unexplored input dimensions to target
            confidence       : 0.0–1.0 confidence in the diagnosis
        """
        afl_text = self._format_afl_stats(afl_stats)
        corpus_text = self._format_corpus_summary(corpus_summary)
        crash_text = self._format_crash_summary(crash_summary)
        best_input_text = self._format_best_queue_input(best_queue_input)

        # Build the FCC deviation section — mirrors reason_along_fcc's attachment
        if deviation_function_name and goal_function_name:
            deviation_section = (
                f'### Deviation Function: "{deviation_function_name}"\n'
                f"{deviation_function_body[:2000]}\n\n"
                f'### Goal Function (next on FCC, not yet reached)\n'
                f"{goal_function_name}\n\n"
            )
            task_stmt = (
                f'The highest-coverage AFL++ input reaches "{deviation_function_name}" '
                f'but fails to proceed to "{goal_function_name}". '
                "Identify what in the deviation function blocks the execution path and "
                "classify why the fuzzer has stalled."
            )
            suggestion_fcc = (
                f'Look at the source of "{deviation_function_name}" to find the specific '
                f'branch or condition that prevents execution from reaching "{goal_function_name}". '
                "Note: macro-defined constants may not appear in the source; infer their "
                "likely values from parameter and variable names. "
            )
        else:
            deviation_section = ""
            task_stmt = (
                "Identify why the directed fuzzer has stalled — no FCC deviation point "
                "could be determined from coverage data."
            )
            suggestion_fcc = ""

        prompt = self._build_query(
            task=task_stmt,
            attachment=(
                f"### Highest-Coverage Input (from AFL++ queue)\n{best_input_text}\n\n"
                f"{deviation_section}"
                f"### AFL++ Runtime Statistics\n{afl_text}\n\n"
                f"### Corpus State\n{corpus_text}\n\n"
                f"### Crash Summary\n{crash_text}\n\n"
                f"### Target Information\n"
                f"Target function : {target_info.get('target_function', 'unknown')}\n"
                f"Bug type        : {target_info.get('bug_type', 'unknown')}\n"
                f"Input format    : {target_info.get('input_format', 'unknown')}\n\n"
                f"### Bug Root Cause (from pre-phase analysis)\n"
                f"Function : {bug_info.get('function', 'unknown')}\n"
                f"Cause    : {bug_info.get('cause', 'unknown')}\n"
                f"Trigger conditions: {', '.join(bug_info.get('trigger_conditions', []))}\n\n"
                f"### Program Usage\n{program_usage}\n\n"
                f"### Plateau Duration\n"
                f"No new coverage for {stuck_duration_s} seconds."
            ),
            suggestion=(
                f"{suggestion_fcc}"
                f"Consider these possible stuck types: {', '.join(STUCK_TYPES)}. "
                "Look for patterns: very low exec/s suggests format barriers, "
                "high paths but no crashes suggests path constraints, identical "
                "corpus sizes suggest mutator bias, low total paths suggest island isolation. "
                "If multiple branches in the deviation function could lead to the goal, "
                "list each as a separate priority gap."
            ),
            answer_template=(
                "Return valid JSON:\n"
                "```json\n"
                "{\n"
                '  "stuck_type": "<one of: island | format_barrier | path_constraint | coverage_cliff | mutator_bias>",\n'
                '  "cause": "<what specific condition in the deviation function blocks progress>",\n'
                '  "hypothesis": "<what change to the input would allow execution to reach the goal function>",\n'
                '  "priority_gaps": [\n'
                '    "<specific branch condition or input property to target>",\n'
                '    "..."\n'
                '  ],\n'
                '  "confidence": <0.0 to 1.0>\n'
                "}\n"
                "```"
            ),
        )

        try:
            result = self._parse_json(self._query_llm(prompt))
            logger.info(
                "[Reassessment] Diagnosis: type=%s deviation=%s→%s confidence=%.2f — %s",
                result.get("stuck_type", "?"),
                deviation_function_name or "?",
                goal_function_name or "?",
                result.get("confidence", 0.0),
                result.get("cause", "")[:100],
            )
            return result
        except (json.JSONDecodeError, KeyError) as e:
            logger.error("Failed to parse diagnosis: %s", e)
            return {
                "stuck_type": "unknown",
                "cause": "Could not determine cause",
                "hypothesis": "Try more diverse seeds",
                "priority_gaps": [],
                "confidence": 0.0,
            }

    # -------------------------------------------------------------------------
    # Call 2: Generate a recovery plan
    # -------------------------------------------------------------------------

    def generate_recovery_plan(
        self,
        diagnosis: dict,
        target_summary: dict,
        program_usage: str,
        bug_info: dict,
        reassessment_count: int,
        failed_strategies: list[str] | None = None,
        coverage_trend: list[dict] | None = None,
    ) -> dict:
        """
        Generate new seeds and mutator adjustments to escape the plateau.

        This is the second (and final) LLM call in the reassessment phase.
        It uses the diagnosis from Call 1 together with the pre-phase function
        summary and program usage to generate a targeted recovery plan.

        The seed format follows the same schema as ReasoningAgent so that
        SeedGenerator.write_seeds() can consume them directly.

        Args:
            diagnosis          : output of diagnose()
            target_summary     : function summary from pre-phase (summarize_function)
            program_usage      : program usage string from config
            bug_info           : extracted bug information from pre-phase
            reassessment_count : how many times reassessment has already fired
            failed_strategies  : from PersistentMemory.get_failed_strategies() —
                                 strategies that did not improve coverage in prior
                                 reassessments; the LLM is told to avoid them
            coverage_trend     : from PersistentMemory.get_coverage_trend() —
                                 recent coverage snapshots for context

        Returns dict with:
            new_seeds      : list of seed dicts (seed_type, seed_content/seed_code,
                             seed_description compatible with write_seeds())
            mutator_focus  : description of what mutator strategies to emphasize
            mutator_update : dict compatible with MutatorGenerator.generate() analysis arg
            rationale      : overall strategy explanation
        """
        stuck_type = diagnosis.get("stuck_type", "unknown")
        hypothesis = diagnosis.get("hypothesis", "")
        priority_gaps = diagnosis.get("priority_gaps", [])
        gaps_text = "\n".join(f"  - {g}" for g in priority_gaps) or "  (none identified)"

        # Tailor the suggestion based on diagnosed stuck type
        type_hint = {
            "island": (
                "Generate seeds with very different format characteristics "
                "to explore a wider region of the input space."
            ),
            "format_barrier": (
                "Focus on seeds that satisfy more format constraints "
                "(magic bytes, headers, checksums) to pass format validation gates."
            ),
            "path_constraint": (
                "Generate seeds targeting the specific branch conditions in the "
                "priority gaps. Try multiple values for ambiguous conditions."
            ),
            "coverage_cliff": (
                "Add small structural variations to existing seeds to push past "
                "the edges that are being repeatedly covered."
            ),
            "mutator_bias": (
                "Design mutators that operate at a higher semantic level "
                "(field-level, not byte-level) to escape the local optimum."
            ),
        }.get(stuck_type, "Generate diverse seeds targeting the priority gaps.")

        # Build optional memory sections for the Attachment
        failed_text = ""
        if failed_strategies:
            failed_text = (
                "\n### Previously Failed Strategies (from persistent memory — do NOT repeat)\n"
                + "\n".join(f"  {s}" for s in failed_strategies)
            )

        trend_text = ""
        if coverage_trend:
            trend_lines = [
                f"  t={int(s.get('timestamp', 0))}: paths={s.get('paths_total', '?')} "
                f"crashes={s.get('unique_crashes', '?')} bitmap={s.get('bitmap_cvg', '?')}"
                for s in coverage_trend
            ]
            trend_text = "\n### Recent Coverage Trend (from persistent memory)\n" + "\n".join(trend_lines)

        prompt = self._build_query(
            task=(
                "Generate a recovery plan with new seeds and updated mutation "
                "strategies to escape the fuzzing plateau."
            ),
            attachment=(
                f"### Diagnosis\n"
                f"Stuck type : {stuck_type}\n"
                f"Cause      : {diagnosis.get('cause', '')}\n"
                f"Hypothesis : {hypothesis}\n"
                f"Priority gaps to target:\n{gaps_text}\n"
                f"{failed_text}"
                f"{trend_text}\n\n"
                f"### Target Function Summary\n"
                f"Function      : {target_summary.get('name', 'unknown')}\n"
                f"Functionality : {target_summary.get('functionality', '')}\n"
                f"Key operations:\n"
                + "\n".join(f"  {op}" for op in target_summary.get("key_operations", []))
                + f"\n\n### Program Usage\n{program_usage}\n\n"
                f"### Bug Information\n"
                f"Cause              : {bug_info.get('cause', '')}\n"
                f"Trigger conditions : {', '.join(bug_info.get('trigger_conditions', []))}\n\n"
                f"### Reassessment Attempt\n"
                f"This is reassessment #{reassessment_count}."
            ),
            suggestion=(
                f"{type_hint} "
                "Generate 3-5 new seeds. Each seed should target a different "
                "priority gap so the fuzzer explores diverse directions simultaneously. "
                "For binary formats (ELF, image, compiled objects), provide a Python "
                "script (seed_type: 'code'); for text inputs provide the string directly "
                "(seed_type: 'string'). "
                "Do NOT repeat any strategy listed under 'Previously Failed Strategies'. "
                "Also specify which mutation strategies should be emphasized going forward."
            ),
            answer_template=(
                "Return valid JSON:\n"
                "```json\n"
                "{\n"
                '  "rationale": "<overall strategy for escaping the plateau>",\n'
                '  "new_seeds": [\n'
                '    {\n'
                '      "seed_description": "<what this seed targets>",\n'
                '      "seed_type": "<string or code>",\n'
                '      "seed_content": "<seed string if seed_type is string, else empty>",\n'
                '      "seed_code": "<Python script to generate seed file if seed_type is code, else empty>"\n'
                '    }\n'
                '  ],\n'
                '  "mutator_focus": "<natural-language description of mutation emphasis>",\n'
                '  "mutation_strategies": [\n'
                '    {"name": "<strategy name>", "description": "<what to mutate and how>"}\n'
                '  ]\n'
                "}\n"
                "```"
            ),
        )

        try:
            result = self._parse_json(self._query_llm(prompt, temperature=0.4))
            n_seeds = len(result.get("new_seeds", []))
            logger.info(
                "[Reassessment] Recovery plan: %d new seeds, focus: %s",
                n_seeds,
                result.get("mutator_focus", "")[:80],
            )
            # Attach the mutator_update sub-dict that MutatorGenerator.generate() expects
            result["mutator_update"] = {
                "bug_info": bug_info,
                "function_summary": target_summary,
                "vulnerability_pattern": bug_info.get("cause", ""),
                "trigger_conditions": bug_info.get("trigger_conditions", []),
                "additional_strategies": result.get("mutation_strategies", []),
            }
            return result
        except (json.JSONDecodeError, KeyError) as e:
            logger.error("Failed to parse recovery plan: %s", e)
            return {
                "rationale": "Fallback: diversify seeds",
                "new_seeds": [],
                "mutator_focus": "increase byte-level diversity",
                "mutation_strategies": [],
                "mutator_update": {},
            }

    # -------------------------------------------------------------------------
    # Helpers: format AFL++ runtime data for LLM context
    # -------------------------------------------------------------------------

    def _format_afl_stats(self, stats: dict) -> str:
        """Format AFL++ fuzzer_stats into a readable summary for the LLM."""
        if not stats:
            return "No stats available."
        fields = [
            ("paths_total",    "Total paths discovered"),
            ("paths_found",    "New paths found"),
            ("unique_crashes", "Unique crashes"),
            ("unique_hangs",   "Unique hangs"),
            ("execs_per_sec",  "Executions/sec"),
            ("execs_done",     "Total executions"),
            ("bitmap_cvg",     "Bitmap coverage"),
            ("stability",      "Stability"),
        ]
        lines = []
        for key, label in fields:
            if key in stats:
                lines.append(f"  {label}: {stats[key]}")
        return "\n".join(lines) if lines else "No relevant stats."

    def _format_corpus_summary(self, summary: dict) -> str:
        """Format corpus statistics for the LLM."""
        if not summary:
            return "No corpus data."
        lines = [
            f"  Seed count   : {summary.get('count', 0)}",
            f"  Total size   : {summary.get('total_bytes', 0)} bytes",
            f"  Size range   : {summary.get('min_size', 0)}–{summary.get('max_size', 0)} bytes",
        ]
        if summary.get("format_sample"):
            lines.append(f"  Format hints : {summary['format_sample']}")
        return "\n".join(lines)

    def _format_crash_summary(self, summary: dict) -> str:
        """Format crash information for the LLM."""
        if not summary:
            return "No crashes yet."
        lines = [f"  Unique crashes: {summary.get('unique_crashes', 0)}"]
        sigs = summary.get("crash_signatures", [])
        if sigs:
            lines.append("  Signatures:")
            for sig in sigs[:5]:
                lines.append(f"    - {sig}")
        return "\n".join(lines)

    def _format_best_queue_input(self, info: dict | None) -> str:
        """Format the highest-coverage queue input for the LLM."""
        if not info:
            return "  (No AFL++ queue input available)"
        lines = [
            f"  File    : {info.get('name', '?')}",
            f"  Size    : {info.get('size', 0)} bytes",
            f"  Hex     : {info.get('hex_preview', '')}",
        ]
        text = info.get("text_preview", "").strip()
        if text:
            lines.append(f"  Content : {text[:200]}")
        return "\n".join(lines)

    # -------------------------------------------------------------------------
    # Helper: build corpus/crash summaries from disk (called by orchestrator)
    # -------------------------------------------------------------------------

    @staticmethod
    def summarize_corpus(corpus_dir: str) -> dict:
        """
        Scan the corpus directory and return a summary dict for diagnose().
        """
        path = Path(corpus_dir)
        if not path.exists():
            return {"count": 0, "total_bytes": 0, "min_size": 0, "max_size": 0}

        files = [f for f in path.iterdir() if f.is_file()]
        if not files:
            return {"count": 0, "total_bytes": 0, "min_size": 0, "max_size": 0}

        sizes = [f.stat().st_size for f in files]
        # Peek at a few files for format hints (first 4 bytes as hex)
        hints = []
        for f in files[:3]:
            try:
                header = f.read_bytes()[:4]
                hints.append(f"{f.name}: {header.hex()}")
            except OSError:
                pass

        return {
            "count": len(files),
            "total_bytes": sum(sizes),
            "min_size": min(sizes),
            "max_size": max(sizes),
            "format_sample": "; ".join(hints),
        }

    @staticmethod
    def summarize_crashes(crashes_dir: str) -> dict:
        """
        Scan the crashes directory and return a summary dict for diagnose().
        """
        path = Path(crashes_dir)
        if not path.exists():
            return {"unique_crashes": 0, "crash_signatures": []}

        # AFL++ names crashes id:000000,... under default/ or directly
        crash_files = list(path.glob("id:*")) + list(path.glob("default/crashes/id:*"))
        signatures = []
        for cf in crash_files[:5]:
            # Use the filename as a lightweight "signature" (contains sig info)
            signatures.append(cf.name[:80])

        return {
            "unique_crashes": len(crash_files),
            "crash_signatures": signatures,
        }

    @staticmethod
    def find_best_queue_input(output_dir: str) -> dict | None:
        """
        Return metadata for the highest-coverage input in the AFL++ queue.

        AFL++ places interesting inputs under <output>/default/queue/ and marks
        those that added new coverage bits with '+cov' in the filename. Among
        those files, the one discovered most recently (highest mtime) represents
        the current coverage frontier. Falls back to any queue file when no
        '+cov' entries exist.

        Returns a dict with: name, size, hex_preview, text_preview — or None
        if no queue directory or files are found.
        """
        base = Path(output_dir)
        for queue_dir in [base / "default" / "queue", base / "queue"]:
            if not queue_dir.is_dir():
                continue
            files = [f for f in queue_dir.iterdir() if f.is_file() and f.name.startswith("id:")]
            if not files:
                continue
            # Prefer inputs that added new coverage bits
            cov_files = [f for f in files if "+cov" in f.name]
            candidates = cov_files if cov_files else files
            # Most recently written = closest to the current coverage frontier
            best = max(candidates, key=lambda f: f.stat().st_mtime)
            try:
                content = best.read_bytes()
            except OSError:
                continue
            text_preview = ""
            try:
                text_preview = content[:256].decode("utf-8", errors="replace")
            except Exception:
                pass
            return {
                "path": str(best),
                "name": best.name,
                "size": len(content),
                "hex_preview": content[:64].hex(),
                "text_preview": text_preview,
            }
        return None
