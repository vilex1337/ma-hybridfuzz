"""
Base LLM Agent - shared infrastructure for ReasoningAgent and ReassessmentAgent.

Provides the RANDLUZZ 4-part stateless query scheme and helpers so that the
concrete agents do not duplicate code.

LLM calls are routed through the provider abstraction in llm.provider, so
subclasses work unchanged across Anthropic, OpenAI (Codex), and Gemini.
"""

import json
import logging
from typing import Any

from llm.provider import create_provider

logger = logging.getLogger("pre_phase.base_agent")


class LLMAgent:
    """
    Base class for MA-HybridFuzz LLM agents.

    Subclasses (ReasoningAgent, ReassessmentAgent) inherit __init__,
    _build_query, _query_llm, and _parse_json so they only need to
    implement their domain-specific methods.
    """

    def __init__(self, config: dict):
        self.config = config
        self.provider = create_provider(config)
        self.model = self.provider.model
        self.max_tokens = config["llm"]["max_tokens"]
        self.default_temperature = config["llm"].get("temperature", 0.2)

    # -------------------------------------------------------------------------
    # RANDLUZZ §3.1 Query Scheme
    # -------------------------------------------------------------------------

    def _build_query(
        self,
        task: str,
        attachment: str = "",
        suggestion: str = "",
        answer_template: str = "",
    ) -> str:
        """
        Build a structured prompt following RANDLUZZ's 4-part query scheme.

        - Task           : the main objective of the query
        - Attachment     : relevant context (function bodies, bug report, prior results)
        - Suggestion     : guidance relevant to the specific task and required answers
        - Answer Template: defines the required content and format of the LLM's response

        Each call is stateless — no historical conversation records are attached.
        If a task requires results from a previous query, those results are included
        in the Attachment and noted in the Suggestion (per §3.1).
        """
        parts = [f"### Task\n{task}"]
        if attachment:
            parts.append(f"### Attachment\n{attachment}")
        if suggestion:
            parts.append(f"### Suggestion\n{suggestion}")
        if answer_template:
            parts.append(f"### Answer Template\n{answer_template}")
        return "\n\n".join(parts)

    def _query_llm(self, prompt: str, temperature: float | None = None) -> str:
        """Send a single stateless query to the LLM and return the raw text."""
        return self.provider.generate(
            prompt=prompt,
            max_tokens=self.max_tokens,
            temperature=self.default_temperature if temperature is None else temperature,
        )

    def _parse_json(self, text: str) -> dict[str, Any]:
        """Parse JSON from LLM text, asserting the result is a dict.

        Handles two common failure modes from real LLM output:
          1. JSON wrapped in ```json … ``` fences.
          2. Multi-line string values containing literal newlines / tabs that
             break strict `json.loads`. A small string-aware repair pass
             escapes those control characters before retrying.
        """
        payload = self._extract_json_block(text)
        try:
            result = json.loads(payload)
        except json.JSONDecodeError:
            # Retry after escaping bare control characters inside strings.
            result = json.loads(_escape_controls_in_strings(payload))
        if not isinstance(result, dict):
            raise ValueError(f"Expected JSON object, got {type(result).__name__}")
        return result

    @staticmethod
    def _extract_json_block(text: str) -> str:
        """Extract the JSON payload from an LLM response, stripping markdown fences."""
        if "```json" in text:
            text = text.split("```json", 1)[1].split("```", 1)[0]
        elif "```" in text:
            text = text.split("```", 1)[1].split("```", 1)[0]
        return text.strip()


def _escape_controls_in_strings(text: str) -> str:
    """Escape bare \\n, \\r, \\t inside JSON string literals.

    LLMs frequently produce JSON with multi-line code in string values
    (Python mutator bodies, seed-generation scripts) that is not valid JSON.
    This state machine walks the text, tracks whether we are inside a string,
    and escapes the usual control characters so strict `json.loads` succeeds.
    """
    out: list[str] = []
    in_string = False
    escape = False
    for ch in text:
        if escape:
            out.append(ch)
            escape = False
            continue
        if ch == "\\" and in_string:
            out.append(ch)
            escape = True
            continue
        if ch == '"':
            in_string = not in_string
            out.append(ch)
            continue
        if in_string:
            if ch == "\n":
                out.append("\\n")
            elif ch == "\r":
                out.append("\\r")
            elif ch == "\t":
                out.append("\\t")
            else:
                out.append(ch)
        else:
            out.append(ch)
    return "".join(out)
