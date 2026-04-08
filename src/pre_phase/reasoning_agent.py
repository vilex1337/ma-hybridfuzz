"""
Reasoning Agent - Analyzes target source code and bug information
to identify feasible paths and constraints for directed fuzzing.
"""

import json
import logging
from pathlib import Path

import anthropic

logger = logging.getLogger("pre_phase.reasoning")


class ReasoningAgent:
    def __init__(self, config: dict):
        self.config = config
        self.client = anthropic.Anthropic()
        self.model = config["llm"]["model"]
        self.max_tokens = config["llm"]["max_tokens"]

    def analyze_target(
        self, source_dir: str, target_function: str, bug_type: str
    ) -> dict:
        """Analyze target source to identify paths, constraints, and entry points."""
        source_snippets = self._collect_source(source_dir, target_function)

        prompt = f"""You are a security researcher analyzing a C/C++ program for directed fuzzing.

Target function: {target_function}
Bug type: {bug_type}

Source code snippets:
{source_snippets}

Analyze and provide a JSON response with:
1. "paths": List of function call chains from entry points to the target function.
   Each path is a list of function names.
2. "constraints": Input constraints needed to reach the target (e.g., magic bytes,
   specific field values, size requirements).
3. "input_format": Description of expected input format (binary, text, structured).
4. "critical_branches": Key branch conditions that must be satisfied to reach target.
5. "vulnerability_pattern": How the bug type manifests in this code.

Return ONLY valid JSON."""

        response = self.client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            temperature=self.config["llm"]["temperature"],
            messages=[{"role": "user", "content": prompt}],
        )

        try:
            text = response.content[0].text
            # Extract JSON from response (handle markdown code blocks)
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0]
            elif "```" in text:
                text = text.split("```")[1].split("```")[0]
            return json.loads(text.strip())
        except (json.JSONDecodeError, IndexError) as e:
            logger.error("Failed to parse LLM response: %s", e)
            return {"paths": [], "constraints": [], "input_format": "unknown",
                    "critical_branches": [], "vulnerability_pattern": ""}

    def reassess(self, current_stats: dict, coverage_dir: str, corpus_dir: str) -> dict:
        """Re-analyze when fuzzer is stuck, using current coverage state."""
        coverage_summary = self._summarize_coverage(coverage_dir)
        corpus_summary = self._summarize_corpus(corpus_dir)

        prompt = f"""You are a security researcher helping a directed fuzzer that is stuck.

Current fuzzing stats:
- Paths discovered: {current_stats.get('paths_total', 0)}
- Unique crashes: {current_stats.get('unique_crashes', 0)}
- Execs/sec: {current_stats.get('execs_per_sec', 'N/A')}

Coverage summary: {coverage_summary}
Corpus summary: {corpus_summary}

The fuzzer has hit a coverage plateau. Analyze the situation and provide:
1. "diagnosis": Why the fuzzer might be stuck.
2. "new_strategies": Specific mutation strategies to try.
3. "paths": New or adjusted paths to explore.
4. "constraints": Additional constraints discovered.
5. "seed_hints": Specific byte patterns or structures for new seeds.

Return ONLY valid JSON."""

        response = self.client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            temperature=0.5,
            messages=[{"role": "user", "content": prompt}],
        )

        try:
            text = response.content[0].text
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0]
            elif "```" in text:
                text = text.split("```")[1].split("```")[0]
            return json.loads(text.strip())
        except (json.JSONDecodeError, IndexError) as e:
            logger.error("Failed to parse reassessment response: %s", e)
            return {"diagnosis": "", "new_strategies": [], "paths": [],
                    "constraints": [], "seed_hints": []}

    def _collect_source(self, source_dir: str, target_function: str) -> str:
        """Collect relevant source code snippets around the target function."""
        snippets = []
        source_path = Path(source_dir)
        if not source_path.exists():
            logger.warning("Source directory not found: %s", source_dir)
            return ""

        for ext in ("*.c", "*.cpp", "*.cc", "*.h", "*.hpp"):
            for fpath in source_path.rglob(ext):
                try:
                    content = fpath.read_text(errors="ignore")
                    if target_function in content:
                        # Include file with context
                        snippets.append(f"// File: {fpath.relative_to(source_path)}\n{content[:4000]}")
                except Exception as e:
                    logger.debug("Could not read %s: %s", fpath, e)

        # Limit total size
        combined = "\n\n".join(snippets)
        if len(combined) > 15000:
            combined = combined[:15000] + "\n... (truncated)"
        return combined

    def _summarize_coverage(self, coverage_dir: str) -> str:
        cov_path = Path(coverage_dir)
        if not cov_path.exists():
            return "No coverage data available"
        files = list(cov_path.iterdir())
        return f"{len(files)} coverage files"

    def _summarize_corpus(self, corpus_dir: str) -> str:
        corp_path = Path(corpus_dir)
        if not corp_path.exists():
            return "No corpus data available"
        files = list(corp_path.iterdir())
        total_size = sum(f.stat().st_size for f in files if f.is_file())
        return f"{len(files)} inputs, total {total_size} bytes"
