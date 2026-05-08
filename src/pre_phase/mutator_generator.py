"""
Mutator Generator - Creates bug-specific custom mutators for AFL++.
(Gap 3 - RANDLUZZ-inspired)
"""

import json
import logging
import shutil
import subprocess
import textwrap
from pathlib import Path

from llm.provider import create_provider
from pre_phase.base_agent import _escape_controls_in_strings

logger = logging.getLogger("pre_phase.mutator_gen")

# Template for AFL++ custom mutator C++ shared library.
# mutation_logic must set *out_buf and return the new buffer size.
MUTATOR_CPP_TEMPLATE = """\
/* Auto-generated AFL++ custom mutator: {name} */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define MAX_FILE (1 << 20)  /* 1 MiB — matches AFL++ default */

typedef struct {{
    unsigned int  seed;
    uint8_t      *mutated_out;
}} MutatorState;

#ifdef __cplusplus
extern "C" {{
#endif

MutatorState *afl_custom_init(void *afl, unsigned int seed) {{
    srand(seed);
    MutatorState *data = (MutatorState *)calloc(1, sizeof(MutatorState));
    if (!data) return NULL;
    data->seed = seed;
    data->mutated_out = (uint8_t *)malloc(MAX_FILE);
    if (!data->mutated_out) {{ free(data); return NULL; }}
    return data;
}}

size_t afl_custom_fuzz(MutatorState *data, uint8_t *buf, size_t buf_size,
                       uint8_t **out_buf, uint8_t *add_buf,
                       size_t add_buf_size, size_t max_size) {{
{mutation_logic}
}}

void afl_custom_deinit(MutatorState *data) {{
    free(data->mutated_out);
    free(data);
}}

#ifdef __cplusplus
}}
#endif
"""


class MutatorGenerator:
    def __init__(self, config: dict):
        self.config = config
        self.provider = create_provider(config)
        self.model = self.provider.model
        self.mutator_dir = Path(config["paths"]["mutators"])
        self.mutator_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, analysis: dict, bug_type: str) -> list[Path]:
        """
        Generate bug-specific AFL++ custom mutators following RANDLUZZ §3.4.

        RANDLUZZ first asks the LLM to produce a Bug Analysis report (cause + how
        to trigger), then generates mutation strategies from that analysis, and
        finally translates those strategies into C-level mutator code.

        Stage 1 - Bug Analysis:
            Input : Bug Info + Function Summary  (from ReasoningAgent outputs)
            Output: bug cause + mutation suggestions

        Stage 2 - Mutator Code Generation:
            Input : mutation suggestions + example mutators
            Output: C++ AFL++ custom mutator code, compiled to .so
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
            bug_analysis_text = self.provider.generate(
                prompt=bug_analysis_prompt,
                max_tokens=self.config["llm"]["max_tokens"],
                temperature=0.2,
            )
        except Exception as e:
            logger.error("Bug analysis LLM call failed: %s", e)
            bug_analysis_text = f"Bug type: {bug_type}\nRoot cause: {vuln_pattern}"

        # ── Stage 2: Mutator Code Generation ─────────────────────────────────
        mutator_prompt = self._build_mutator_generation_query(
            bug_type=bug_type,
            bug_analysis=bug_analysis_text,
        )
        response_text = self.provider.generate(
            prompt=mutator_prompt,
            max_tokens=self.config["llm"]["max_tokens"],
            temperature=self.config["llm"]["temperature"],
        )

        mutators = self._parse_mutators(response_text)
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
        Stage 2 of §3.4: translate mutation strategies into AFL++ C++ mutator code.

        Per RANDLUZZ, real C mutator code examples are included as context.
        """
        return (
            f"### Task\n"
            f"Translate the following mutation strategies into AFL++ custom mutator "
            f"C++ functions.\n\n"
            f"### Attachment\n"
            f"Bug Analysis:\n{bug_analysis}\n\n"
            f"Example mutation_logic body (replaces the function body of afl_custom_fuzz):\n"
            f"```c\n"
            f"    /* copy input into pre-allocated buffer and append a null byte */\n"
            f"    size_t new_size = buf_size + 1;\n"
            f"    if (new_size > max_size) new_size = max_size;\n"
            f"    memcpy(data->mutated_out, buf, buf_size);\n"
            f"    if (new_size > buf_size) data->mutated_out[buf_size] = 0x00;\n"
            f"    *out_buf = data->mutated_out;\n"
            f"    return new_size;\n"
            f"```\n\n"
            f"### Suggestion\n"
            f"Generate 3-5 mutators, one per strategy. Each mutation_logic:\n"
            f"- Is pure C (no C++ features needed, but C++ is allowed)\n"
            f"- Has access to: data (MutatorState*, with data->mutated_out pre-allocated to MAX_FILE bytes),\n"
            f"  buf (uint8_t*), buf_size (size_t), add_buf (uint8_t*),\n"
            f"  add_buf_size (size_t), max_size (size_t), out_buf (uint8_t**)\n"
            f"- Must copy/write into data->mutated_out, set *out_buf = data->mutated_out, and return the new size\n"
            f"- Must NOT malloc a new buffer — reuse data->mutated_out\n"
            f"- Must not use global state\n"
            f"- May use rand() for randomness (seeded in afl_custom_init)\n\n"
            f"### Answer Template\n"
            f"Return valid JSON:\n"
            f"```json\n"
            f"{{\n"
            f'  "mutators": [\n'
            f"    {{\n"
            f'      "name": "<alphanumeric_underscore_name>",\n'
            f'      "description": "<what this mutator does>",\n'
            f'      "mutation_logic": "<C code body indented 4 spaces; sets *out_buf, returns size_t>"\n'
            f"    }}\n"
            f"  ]\n"
            f"}}\n"
            f"```"
        )

    def _parse_mutators(self, text: str) -> list[dict]:
        # Strip markdown fence if present
        if "```json" in text:
            text = text.split("```json", 1)[1].split("```", 1)[0]
        elif "```" in text:
            text = text.split("```", 1)[1].split("```", 1)[0]
        payload = text.strip()
        # Retry with control-char escaping inside strings — LLMs often return
        # Python code in string values with bare newlines.
        for attempt in (payload, _escape_controls_in_strings(payload)):
            try:
                data = json.loads(attempt)
                return data.get("mutators", []) if isinstance(data, dict) else []
            except json.JSONDecodeError:
                continue
        logger.error("Failed to parse mutator response (both strict and repaired).")
        return []

    def _save_mutators(self, mutators: list[dict]) -> list[Path]:
        saved = []
        for mutator in mutators:
            name = mutator.get("name", "unknown_mutator")
            name = "".join(c for c in name if c.isalnum() or c == "_") or "unknown_mutator"
            logic = mutator.get(
                "mutation_logic",
                "    size_t out_size = buf_size;\n"
                "    uint8_t *copy = (uint8_t *)malloc(out_size);\n"
                "    if (!copy) {\n"
                "        *out_buf = buf;\n"
                "        return buf_size;\n"
                "    }\n"
                "    if (out_size > 0) {\n"
                "        memcpy(copy, buf, out_size);\n"
                "    }\n"
                "    *out_buf = copy;\n"
                "    return out_size;",
            )

            indented = textwrap.indent(textwrap.dedent(logic), "    ")
            content = MUTATOR_CPP_TEMPLATE.format(name=name, mutation_logic=indented)

            cpp_path = self.mutator_dir / f"mutator_{name}.cpp"
            cpp_path.write_text(content)

            so_path = self._compile_mutator(cpp_path)
            if so_path:
                saved.append(so_path)
                logger.info("Compiled mutator: %s", so_path.name)
            else:
                logger.warning("Skipping mutator %s — compile failed", name)

        return saved

    def _compile_mutator(self, cpp_path: Path) -> Path | None:
        compiler = shutil.which("clang++") or shutil.which("g++")
        if not compiler:
            logger.error("No C++ compiler found; cannot compile mutator %s", cpp_path.name)
            return None

        so_path = cpp_path.with_suffix(".so")
        cmd = [compiler, "-shared", "-fPIC", "-O2", "-o", str(so_path), str(cpp_path)]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            logger.error("Compiler error for %s: %s", cpp_path.name, exc)
            return None

        if result.returncode != 0:
            logger.error(
                "Compile failed for %s:\n%s", cpp_path.name, result.stderr.strip()
            )
            return None

        return so_path
