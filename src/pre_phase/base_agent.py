"""
Base LLM Agent - shared infrastructure for ReasoningAgent and ReassessmentAgent.

Provides the RANDLUZZ 4-part stateless query scheme and helpers so that the
concrete agents do not duplicate code.
"""

import json
import logging
from typing import Any

import anthropic
from anthropic.types import TextBlock

logger = logging.getLogger("pre_phase.base_agent")


class LLMAgent:
    """
    Base class for MA-HybridFuzz LLM agents.

    Subclasses (ReasoningAgent, ReassessmentAgent) inherit __init__,
    _build_query, _query_llm, _extract_text, and _parse_json so they
    only need to implement their domain-specific methods.
    """

    def __init__(self, config: dict):
        self.config = config
        self.client = anthropic.Anthropic()
        self.model = config["llm"]["model"]
        self.max_tokens = config["llm"]["max_tokens"]

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

    def _query_llm(self, prompt: str, temperature: float = 0.2) -> str:
        """Send a single stateless query to the LLM and return the raw text."""
        response = self.client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            temperature=temperature,
            messages=[{"role": "user", "content": prompt}],
        )
        return self._extract_text(response)

    @staticmethod
    def _extract_text(response: anthropic.types.Message) -> str:
        """Return the text from the first TextBlock in an Anthropic response.

        response.content is a union of block types (TextBlock, ToolUseBlock,
        ThinkingBlock, …). Only TextBlock carries a .text attribute; using
        isinstance narrows the type so pyright accepts the attribute access.
        """
        for block in response.content:
            if isinstance(block, TextBlock):
                return block.text
        return ""

    def _parse_json(self, text: str) -> dict[str, Any]:
        """Parse JSON from LLM text, asserting the result is a dict."""
        if "```json" in text:
            text = text.split("```json")[1].split("```")[0]
        elif "```" in text:
            text = text.split("```")[1].split("```")[0]
        result = json.loads(text.strip())
        if not isinstance(result, dict):
            raise ValueError(f"Expected JSON object, got {type(result).__name__}")
        return result
