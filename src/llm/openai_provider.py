"""
OpenAI (Codex) backend for the MA-HybridFuzz LLM abstraction.

Handles two API dialects:
  - Standard chat models (gpt-4o, gpt-4o-mini, gpt-5, gpt-5-mini) use
    temperature + max_tokens.
  - Reasoning models (o1, o1-mini, o3*) ignore temperature and use
    max_completion_tokens.
"""

import logging
import os

from openai import OpenAI

from llm.provider import LLMProvider

logger = logging.getLogger("llm.openai")


class OpenAIProvider(LLMProvider):
    def __init__(self, model: str):
        if not os.getenv("OPENAI_API_KEY"):
            raise RuntimeError(
                "OPENAI_API_KEY is not set. Export it or add it to .env."
            )
        self.model = model
        self.client = OpenAI()

    def generate(
        self,
        prompt: str,
        max_tokens: int = 4096,
        temperature: float = 0.3,
    ) -> str:
        is_reasoning_model = self.model.startswith(("o1", "o3"))

        kwargs: dict = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
        }
        if is_reasoning_model:
            # Reasoning models: no temperature support, use max_completion_tokens.
            kwargs["max_completion_tokens"] = max_tokens
        else:
            kwargs["max_tokens"] = max_tokens
            kwargs["temperature"] = temperature

        response = self.client.chat.completions.create(**kwargs)
        if response.usage:
            self._add_usage(response.usage.prompt_tokens, response.usage.completion_tokens)
        content = response.choices[0].message.content
        return content or ""
