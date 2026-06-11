"""Anthropic (Claude) backend for the MA-HybridFuzz LLM abstraction."""

import logging
import os

import anthropic
from anthropic.types import TextBlock

from llm.provider import LLMProvider

logger = logging.getLogger("llm.anthropic")


class AnthropicProvider(LLMProvider):
    """Thin wrapper around anthropic.Anthropic().messages.create."""

    def __init__(self, model: str):
        if not os.getenv("ANTHROPIC_API_KEY"):
            raise RuntimeError(
                "ANTHROPIC_API_KEY is not set. Export it or add it to .env."
            )
        self.model = model
        self.client = anthropic.Anthropic()

    def generate(
        self,
        prompt: str,
        max_tokens: int = 4096,
        temperature: float = 0.3,
    ) -> str:
        response = self.client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            temperature=temperature,
            messages=[{"role": "user", "content": prompt}],
        )
        self._add_usage(response.usage.input_tokens, response.usage.output_tokens)
        for block in response.content:
            if isinstance(block, TextBlock):
                return block.text
        return ""
