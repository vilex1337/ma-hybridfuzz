"""
Mutator Generator - Creates bug-specific custom mutators for AFL++.
(Gap 3 - RANDLUZZ-inspired)
"""

import json
import logging
import textwrap
from pathlib import Path

import anthropic
from anthropic.types import TextBlock

logger = logging.getLogger("pre_phase.mutator_gen")

# Template for AFL++ custom mutator Python module.
# NOTE: mutation_logic is inserted via str.format(); any literal braces in the
# generated logic are pre-escaped ({{ / }}) before the call so that Python's
# str.format() does not misinterpret dict-literals or f-string-like patterns.
MUTATOR_TEMPLATE = '''"""Auto-generated custom mutator for AFL++: {name}"""

import struct
import random


def init(seed):
    random.seed(seed)


def fuzz(buf, add_buf, max_size):
    """Mutate input buffer. Returns mutated buffer."""
    buf = bytearray(buf)
    if len(buf) == 0:
        buf = bytearray(b"\\x00" * 64)

{mutation_logic}

    return bytes(buf[:max_size])


def describe(max_description_length):
    return b"{name}"[:max_description_length]
'''


class MutatorGenerator:
    def __init__(self, config: dict):
        self.config = config
        self.client = anthropic.Anthropic()
        self.model = config["llm"]["model"]
        self.mutator_dir = Path(config["paths"]["mutators"])
        self.mutator_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, analysis: dict, bug_type: str) -> list[Path]:
        """
        Generate bug-specific AFL++ custom mutators following RANDLUZZ §3.4.

        RANDLUZZ first asks the LLM to produce a Bug Analysis report (cause + how
        to trigger), then generates mutation strategies from that analysis, and
        finally translates those strategies into C-level mutator code.  Here we
        implement that same two-stage reasoning using the 4-part query scheme.

        Stage 1 - Bug Analysis:
            Input : Bug Info + Function Summary  (from ReasoningAgent outputs)
            Output: bug cause + mutation suggestions

        Stage 2 - Mutator Code Generation:
            Input : mutation suggestions + example mutators
            Output: Python AFL++ custom mutator code
        """
        bug_info = analysis.get("bug_info", {})
        func_summary = analysis.get("function_summary", {})
        vuln_pattern = analysis.get("vulnerability_pattern", bug_info.get("cause", ""))
        trigger_conditions = analysis.get(
            "trigger_conditions", bug_info.get("trigger_conditions", [])
        )

        # ── Stage 1: Bug Analysis ─────────────────────────────────────────────
        bug_analysis_prompt = self._build_bug_analysis_query(
            bug_type=bug_type,
            vuln_pattern=vuln_pattern,
            func_summary=func_summary,
            trigger_conditions=trigger_conditions,
        )
        try:
            analysis_response = self.client.messages.create(
                model=self.model,
                max_tokens=self.config["llm"]["max_tokens"],
                temperature=0.2,
                messages=[{"role": "user", "content": bug_analysis_prompt}],
            )
            bug_analysis_text = next(
                (b.text for b in analysis_response.content if isinstance(b, TextBlock)), ""
            )
        except Exception as e:
            logger.error("Bug analysis LLM call failed: %s", e)
            bug_analysis_text = f"Bug type: {bug_type}\nRoot cause: {vuln_pattern}"

        # ── Stage 2: Mutator Code Generation ─────────────────────────────────
        mutator_prompt = self._build_mutator_generation_query(
            bug_type=bug_type,
            bug_analysis=bug_analysis_text,
        )
        response = self.client.messages.create(
            model=self.model,
            max_tokens=self.config["llm"]["max_tokens"],
            temperature=self.config["llm"]["temperature"],
            messages=[{"role": "user", "content": mutator_prompt}],
        )

        mutators = self._parse_mutators(
            next((b.text for b in response.content if isinstance(b, TextBlock)), "")
        )
        saved = self._save_mutators(mutators)
        return saved

    # -------------------------------------------------------------------------
    # RANDLUZZ §3.1 Query Scheme helpers
    # -------------------------------------------------------------------------

    def _build_bug_analysis_query(
        self,
        bug_type: str,
        vuln_pattern: str,
        func_summary: dict,
        trigger_conditions: list[str],
    ) -> str:
        """
        Stage 1 of §3.4: ask the LLM for a Bug Analysis report.

        RANDLUZZ uses Bug Info + Function Summary as input to get the bug cause
        and mutation suggestions that will drive mutator code generation.
        """
        conditions_text = "\n".join(f"  - {c}" for c in trigger_conditions) or "  (not specified)"
        func_text = (
            f"Functionality: {func_summary.get('functionality', '')}\n"
            f"Key Operations:\n"
            + "\n".join(f"  {op}" for op in func_summary.get("key_operations", []))
        ) if func_summary else "(no function summary available)"

        return (
            f"### Task\n"
            f"Perform a bug analysis for the following vulnerability and provide "
            f"mutation suggestions to trigger it.\n\n"
            f"### Attachment\n"
            f"Bug Type: {bug_type}\n"
            f"Root Cause: {vuln_pattern}\n"
            f"Known Trigger Conditions:\n{conditions_text}\n\n"
            f"### Function Summary\n{func_text}\n\n"
            f"### Suggestion\n"
            f"Explain the vulnerability cause precisely and suggest concrete mutation "
            f"strategies (e.g. alter relocation section prefixes, inject non-ASCII "
            f"characters, create overlapping sections). Be specific about which fields "
            f"or bytes to mutate.\n\n"
            f"### Answer Template\n"
            f"# Vulnerability Explanation\n"
            f"<clear explanation of the bug cause>\n\n"
            f"# Mutation Strategies\n"
            f"1. <strategy name>: <description of what to mutate and how>\n"
            f"2. ...\n"
        )

    def _build_mutator_generation_query(
        self, bug_type: str, bug_analysis: str
    ) -> str:
        """
        Stage 2 of §3.4: translate mutation strategies into AFL++ mutator code.

        Per RANDLUZZ, real C mutator code examples are included as context.
        Here we include a Python AFL++ equivalent since the codebase uses Python mutators.
        """
        return (
            f"### Task\n"
            f"Translate the following mutation strategies into AFL++ custom mutator "
            f"Python functions.\n\n"
            f"### Attachment\n"
            f"Bug Analysis:\n{bug_analysis}\n\n"
            f"Example Mutator Structure:\n"
            f"```python\n"
            f"def fuzz(buf, add_buf, max_size):\n"
            f"    buf = bytearray(buf)\n"
            f"    # mutation logic here\n"
            f"    return bytes(buf[:max_size])\n"
            f"```\n\n"
            f"### Suggestion\n"
            f"Generate 3-5 mutators, one per strategy. Each mutator function should "
            f"implement exactly one strategy. Use `struct`, `random`, and `len(buf)`. "
            f"Ensure the code compiles and runs without errors.\n\n"
            f"### Answer Template\n"
            f"Return valid JSON:\n"
            f"```json\n"
            f"{{\n"
            f'  "mutators": [\n'
            f"    {{\n"
            f'      "name": "<alphanumeric_underscore_name>",\n'
            f'      "description": "<what this mutator does>",\n'
            f'      "mutation_logic": "<Python code body, indented 4 spaces, modifies buf bytearray>"\n'
            f"    }}\n"
            f"  ]\n"
            f"}}\n"
            f"```"
        )

    def _parse_mutators(self, text: str) -> list[dict]:
        try:
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0]
            elif "```" in text:
                text = text.split("```")[1].split("```")[0]
            data = json.loads(text.strip())
            return data.get("mutators", [])
        except (json.JSONDecodeError, IndexError) as e:
            logger.error("Failed to parse mutator response: %s", e)
            return []

    def _save_mutators(self, mutators: list[dict]) -> list[Path]:
        saved = []
        for mutator in mutators:
            name = mutator.get("name", "unknown_mutator")
            name = "".join(c for c in name if c.isalnum() or c == "_") or "unknown_mutator"
            logic = mutator.get("mutation_logic", "    pass")

            # Normalise indentation: dedent then re-indent to exactly 4 spaces.
            # textwrap.dedent removes common leading whitespace; textwrap.indent
            # then re-applies a uniform 4-space prefix. This avoids the previous
            # heuristic that double-indented already-indented lines.
            indented = textwrap.indent(textwrap.dedent(logic), "    ")

            # Escape any literal braces in the generated code so that
            # str.format() does not misinterpret dict literals or similar
            # constructs (e.g. `d = {key: val}` → KeyError without escaping).
            escaped_logic = indented.replace("{", "{{").replace("}", "}}")
            content = MUTATOR_TEMPLATE.format(name=name, mutation_logic=escaped_logic)

            fpath = self.mutator_dir / f"mutator_{name}.py"
            fpath.write_text(content)
            saved.append(fpath)
            logger.info("Saved mutator: %s", name)

        return saved
