"""
Reasoning Agent - Implements RANDLUZZ's LLM-based pre-phase reasoning.

RANDLUZZ (Feng et al., 2025) has three pre-phase reasoning stages:
  1. Bug Information  - extract target location and bug cause from CVE/bug report
  2. Function Summary - summarize each function's functionality, parameters, operations
  3. Reachable Seed Generation (three paths):
       a. Preliminary seed  - initial seed from Program Usage + Function Summary
       b. Along FCC         - iterative seed optimization following the Function Call Chain
       c. Based on Functionality - fallback when FCC is incomplete (indirect calls)

All LLM interactions follow RANDLUZZ's 4-part stateless query scheme:
    Task / Attachment / Suggestion / Answer Template
No historical conversation records are included between queries to reduce tokens.
"""

import json
import logging
from typing import Any

from pre_phase.base_agent import LLMAgent

logger = logging.getLogger("pre_phase.reasoning")


class ReasoningAgent(LLMAgent):
    """
    LLM reasoning agent faithfully implementing the RANDLUZZ pre-phase methodology.

    Public API (called by the orchestrator):
      extract_bug_info(bug_report)                      -> dict
      summarize_function(name, declaration, body)       -> dict
      generate_preliminary_seed(target, summary, usage) -> dict
      reason_along_fcc(...)                             -> dict
      reason_based_on_functionality(...)                -> dict
    """

    # _build_query, _query_llm, _extract_text, _parse_json inherited from LLMAgent.

    # -------------------------------------------------------------------------
    # 3.2.1  Bug Information
    # -------------------------------------------------------------------------

    def extract_bug_info(self, bug_report: str) -> dict:
        """
        Extract structured bug information from a CVE/bug report (§3.2.1).

        RANDLUZZ uses LLMs here because they excel at synthesizing natural-language
        content. The extracted information pinpoints the target location and provides
        the bug cause that is later used to generate mutation suggestions.

        Returns:
            version            : affected software version string
            file               : vulnerable source file path
            function           : vulnerable function name
            cause              : brief description of the root cause
            vulnerability_type : e.g. "heap-buffer-overflow", "null-ptr-deref"
        """
        prompt = self._build_query(
            task="Extract bug information from the following CVE/bug report.",
            attachment=f"### Bug Report\n{bug_report}",
            suggestion=(
                "Focus on: the affected software version, the vulnerable file and "
                "function name, and the root cause of the vulnerability. "
                "If the report does not directly state the function name, infer it "
                "from context clues such as stack traces or code references. "
                "Additionally, identify any details about how the bug can be triggered "
                "that will assist in constructing bug-specific mutators."
            ),
            answer_template=(
                "Your answer should be valid JSON:\n"
                "```json\n"
                "{\n"
                '  "version": "<affected software version>",\n'
                '  "file": "<vulnerable source file, e.g. src/rdppm.c>",\n'
                '  "function": "<vulnerable function name>",\n'
                '  "cause": "<brief root cause description>",\n'
                '  "vulnerability_type": "<e.g. heap-buffer-overflow>",\n'
                '  "trigger_conditions": ["<condition 1>", "<condition 2>"]\n'
                "}\n"
                "```"
            ),
        )
        try:
            return self._parse_json(self._query_llm(prompt))
        except (json.JSONDecodeError, KeyError) as e:
            logger.error("Failed to parse bug info: %s", e)
            return {
                "version": "", "file": "", "function": "",
                "cause": "", "vulnerability_type": "", "trigger_conditions": [],
            }

    # -------------------------------------------------------------------------
    # 3.2.3  Function Summary
    # -------------------------------------------------------------------------

    def summarize_function(
        self, func_name: str, func_declaration: str, func_body: str
    ) -> dict:
        """
        Generate a structured Function Summary for a single function (§3.2.3).

        RANDLUZZ generates summaries for all functions in the FCC (and their
        neighbors) because summaries are reused across multiple reasoning stages.
        The summary captures functionality, parameters, and key operations so that
        the LLM can reason about path constraints without re-reading full code.

        Per the paper, the Answer Template requests:
          - Functionality Summaries
          - Parameter Summaries
          - Key Operations

        Returns:
            name           : function name
            functionality  : what the function does
            parameters     : list of parameter descriptions
            key_operations : list of key operations / checks
            raw_summary    : full summary text for downstream prompts
        """
        prompt = self._build_query(
            task=f'Summarize the "{func_name}" below.',
            attachment=(
                f'### Function Body - "{func_name}"\n'
                f"{func_declaration}\n"
                f"{func_body[:3000]}"
            ),
            suggestion=(
                "Please label any magic numbers or compile-time constants in the "
                "function with their likely semantic meaning (e.g. 0xFF -> max byte "
                "value, 255 -> MAXSAMPLE). This helps later reasoning about branch "
                "conditions that depend on macro-defined constants."
            ),
            answer_template=(
                "Your answer should follow this structure:\n"
                "```Function Summary\n"
                "# Functionality Summaries\n"
                "<describe what this function does>\n\n"
                "# Parameter Summaries\n"
                "1. <param_name>: <role and expected values>\n"
                "2. ...\n\n"
                "# Key Operations\n"
                "1. <important check or operation>\n"
                "2. ...\n"
                "```"
            ),
        )
        raw = self._query_llm(prompt)
        return self._parse_function_summary(func_name, raw)

    def _parse_function_summary(self, func_name: str, text: str) -> dict:
        """Parse RANDLUZZ-style function summary into a structured dict."""
        result: dict[str, Any] = {
            "name": func_name,
            "functionality": "",
            "parameters": [],
            "key_operations": [],
            "raw_summary": text,
        }
        # Strip code fence if present
        body = text
        if "```" in body:
            parts = body.split("```")
            # Take the content of the first fence block
            body = parts[1] if len(parts) > 1 else body
            if body.startswith("Function Summary"):
                body = body[len("Function Summary"):].lstrip()

        sections = body.split("#")
        for section in sections:
            section = section.strip()
            if not section:
                continue
            header, _, content = section.partition("\n")
            header_lower = header.lower()
            content = content.strip()
            if "functionality" in header_lower:
                result["functionality"] = content
            elif "parameter" in header_lower:
                result["parameters"] = [
                    line.strip() for line in content.splitlines() if line.strip()
                ]
            elif "key operations" in header_lower or "key operation" in header_lower:
                result["key_operations"] = [
                    line.strip() for line in content.splitlines() if line.strip()
                ]
        return result

    # -------------------------------------------------------------------------
    # 3.3.1  Preliminary Seed Generation
    # -------------------------------------------------------------------------

    def generate_preliminary_seed(
        self,
        target_function: str,
        func_summary: dict,
        program_usage: str,
    ) -> dict:
        """
        Generate a preliminary seed and the command line to activate the target (§3.3.1).

        RANDLUZZ first compares the target function's functionality with Program Usage
        to identify which command option exercises that code path, then generates an
        initial seed matching the required input format.

        For complex binary inputs (ELF, PPM, image files) the LLM generates a Python
        script that creates the file; for simple string inputs it provides the string
        directly (§3.3.4).

        The generated command will be fixed for subsequent fuzzing; only the seed
        (input file) will be mutated.

        Returns:
            command          : full command-line template (use @@ for input placeholder)
            seed_description : human-readable description of what the seed contains
            input_format     : e.g. "PPM image", "ELF binary", "text string"
            seed_type        : "string" (direct) or "code" (Python script)
            seed_content     : the seed string if seed_type == "string"
            seed_code        : Python script to produce seed file if seed_type == "code"
        """
        prompt = self._build_query(
            task=(
                f'Analyze which program command is most likely to activate the target '
                f'function "{target_function}", and generate a preliminary seed input '
                f"for that command."
            ),
            attachment=(
                f'### Function Summary - "{target_function}"\n'
                f"Functionality: {func_summary.get('functionality', '')}\n"
                f"Key Operations:\n"
                + "\n".join(f"  {op}" for op in func_summary.get("key_operations", []))
                + f"\n\n### Program Usage\n{program_usage}"
            ),
            suggestion=(
                "Command options significantly impact which code regions are exercised. "
                "Select the command that is most likely to reach the target function "
                "based on its functionality and the program usage description. "
                "For complex binary formats (ELF, images, compiled objects), provide "
                "a Python script (seed_type: 'code') that generates the seed file when "
                "executed. For simple text or string inputs, provide the seed directly "
                "(seed_type: 'string'). The generated command will be fixed; only the "
                "input seed will be mutated during fuzzing."
            ),
            answer_template=(
                "Your answer should be valid JSON:\n"
                "```json\n"
                "{\n"
                '  "command": "<full command, use @@ as input file placeholder>",\n'
                '  "seed_description": "<what this seed contains and why it reaches the target>",\n'
                '  "input_format": "<e.g. P6 PPM image / ELF binary / ASCII text>",\n'
                '  "seed_type": "<string or code>",\n'
                '  "seed_content": "<seed string if seed_type is string, else empty string>",\n'
                '  "seed_code": "<Python script to generate seed file if seed_type is code, else empty string>"\n'
                "}\n"
                "```"
            ),
        )
        try:
            return self._parse_json(self._query_llm(prompt, temperature=0.3))
        except (json.JSONDecodeError, KeyError) as e:
            logger.error("Failed to parse preliminary seed response: %s", e)
            return {
                "command": "", "seed_description": "", "input_format": "unknown",
                "seed_type": "string", "seed_content": "", "seed_code": "",
            }

    # -------------------------------------------------------------------------
    # 3.3.2  Reasoning Along Function Call Chain
    # -------------------------------------------------------------------------

    def reason_along_fcc(
        self,
        current_input_description: str,
        deviation_function_name: str,
        deviation_function_body: str,
        examined_lines: list[str],
        goal_function_name: str,
        program_usage: str,
    ) -> dict:
        """
        Optimize the current seed by reasoning along the FCC (§3.3.2).

        When the current input causes execution to deviate from the FCC at
        `deviation_function_name` (i.e. it takes a branch that does not lead
        toward the target), RANDLUZZ asks the LLM how the input must be modified
        so that execution instead reaches `goal_function_name` (the next function
        along the complete FCC toward the target).

        The LLM is explicitly told that macro definitions are unavailable so that
        it infers likely constant values from parameter names (§3.3.2). Multiple
        candidate seeds are generated when branch conditions are ambiguous.

        Args:
            current_input_description : description of the current seed / execution path
            deviation_function_name   : function where execution deviates from FCC
            deviation_function_body   : source of the deviation function (for context)
            examined_lines            : the lines in deviation_function that were reached
            goal_function_name        : next target along the FCC to reach
            program_usage             : program usage context (from RAG stage)

        Returns:
            modification_rationale : why this change should redirect execution
            seed_type              : "string" or "code"
            seed_content           : modified seed if seed_type == "string"
            seed_code              : Python script to generate seed if seed_type == "code"
            candidate_seeds        : list of alternative seeds for ambiguous branches
        """
        examined_text = (
            "\n".join(examined_lines) if examined_lines else "(no lines recorded)"
        )
        prompt = self._build_query(
            task=(
                "Based on the provided function body and the current input that leads "
                "to a specific execution path, how should the input be modified to "
                f'guide the program to reach the target function "{goal_function_name}"?'
            ),
            attachment=(
                f"### Current Input\n{current_input_description}\n\n"
                f'### Definition of "{deviation_function_name}"\n'
                f"{deviation_function_body[:2000]}\n\n"
                f'### Examined Lines in "{deviation_function_name}" '
                f"(reached by current input)\n"
                f"{examined_text}\n\n"
                f"### Goal\n"
                f"Reach function: {goal_function_name}\n\n"
                f"### Program Usage\n{program_usage}"
            ),
            suggestion=(
                "Note: macro-defined constants (e.g. MAXSAMPLE, JCS_EXT_RGB) are not "
                "shown in the function body. Infer the potential roles of parameters "
                "and variables from their names. If multiple branches could lead to "
                "the goal, generate multiple candidate seeds to test each possibility."
            ),
            answer_template=(
                "Your answer should be valid JSON:\n"
                "```json\n"
                "{\n"
                '  "modification_rationale": "<why these changes redirect execution to the goal>",\n'
                '  "seed_type": "<string or code>",\n'
                '  "seed_content": "<modified seed if seed_type is string, else empty>",\n'
                '  "seed_code": "<Python script to produce seed file if seed_type is code, else empty>",\n'
                '  "candidate_seeds": [\n'
                '    {"description": "<what this candidate tests>", "seed_content": "<content or empty>", "seed_code": "<code or empty>"}\n'
                "  ]\n"
                "}\n"
                "```"
            ),
        )
        try:
            return self._parse_json(self._query_llm(prompt, temperature=0.3))
        except (json.JSONDecodeError, KeyError) as e:
            logger.error("Failed to parse FCC reasoning response: %s", e)
            return {
                "modification_rationale": "",
                "seed_type": "string", "seed_content": "", "seed_code": "",
                "candidate_seeds": [],
            }

    # -------------------------------------------------------------------------
    # 3.3.3  Reasoning Based on Functionality (fallback - incomplete FCC)
    # -------------------------------------------------------------------------

    def reason_based_on_functionality(
        self,
        target_function: str,
        target_func_summary: dict,
        neighbor_function_name: str,
        neighbor_func_summary: dict,
        program_usage: str,
    ) -> dict:
        """
        Generate a seed to reach a neighbor function when the FCC is incomplete (§3.3.3).

        Static analysis may fail to produce a complete FCC due to:
          - Indirect calls via function pointers
          - Calls through macro-computed addresses
          - Complex control flow that Clang AST cannot resolve

        In this case RANDLUZZ randomly selects a neighboring function of the target
        and asks the LLM to generate inputs that reach it, based on its functionality
        and the Program Usage. If those inputs successfully reach the neighbor,
        RANDLUZZ then applies FCC-based reasoning (§3.3.2) starting from there.

        Args:
            target_function        : the ultimate target vulnerable function
            target_func_summary    : summary of the target function
            neighbor_function_name : a function adjacent to the target in the call graph
            neighbor_func_summary  : summary of the neighbor function
            program_usage          : program usage context (from RAG stage)

        Returns:
            command      : command line to use (with @@ for input)
            rationale    : why this input reaches the neighbor function
            seed_type    : "string" or "code"
            seed_content : seed string if seed_type == "string"
            seed_code    : Python script to generate seed if seed_type == "code"
        """
        prompt = self._build_query(
            task=(
                f'Generate a program input that exercises the function '
                f'"{neighbor_function_name}", which is a neighbor of the '
                f'target function "{target_function}".'
            ),
            attachment=(
                f'### Target Function Summary - "{target_function}"\n'
                f"Functionality: {target_func_summary.get('functionality', '')}\n\n"
                f'### Neighbor Function Summary - "{neighbor_function_name}"\n'
                f"Functionality: {neighbor_func_summary.get('functionality', '')}\n"
                "Key Operations:\n"
                + "\n".join(
                    f"  {op}"
                    for op in neighbor_func_summary.get("key_operations", [])
                )
                + f"\n\n### Program Usage\n{program_usage}"
            ),
            suggestion=(
                "The complete function call chain from the program entry point to the "
                "target is unavailable due to indirect calls or function pointers. "
                "Focus on the neighbor function's functionality and the program usage "
                "to infer which command options and input format will reach it. "
                "Infer parameter roles from names."
            ),
            answer_template=(
                "Your answer should be valid JSON:\n"
                "```json\n"
                "{\n"
                '  "command": "<command line with @@ for input file>",\n'
                '  "rationale": "<why this input reaches the neighbor function>",\n'
                '  "seed_type": "<string or code>",\n'
                '  "seed_content": "<seed if seed_type is string, else empty>",\n'
                '  "seed_code": "<Python script to produce seed if seed_type is code, else empty>"\n'
                "}\n"
                "```"
            ),
        )
        try:
            return self._parse_json(self._query_llm(prompt, temperature=0.3))
        except (json.JSONDecodeError, KeyError) as e:
            logger.error("Failed to parse functionality-based reasoning: %s", e)
            return {
                "command": "", "rationale": "",
                "seed_type": "string", "seed_content": "", "seed_code": "",
            }
