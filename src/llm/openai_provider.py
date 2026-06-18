"""
OpenAI backend for the MA-HybridFuzz LLM abstraction.

Handles two API dialects:
  - Standard chat models (gpt-4o, gpt-4o-mini, gpt-5, ...) use
    temperature + max_tokens.
  - Reasoning models (o1/o3/o4 family, e.g. o4-mini) ignore temperature and use
    max_completion_tokens.
"""

import logging
import os
import re

from openai import OpenAI

from llm.provider import LLMProvider

logger = logging.getLogger("llm.openai")

# Reasoning models are named o<digit>[...]: o1, o1-mini, o3, o4-mini, ...
_REASONING_RE = re.compile(r"^o\d")


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
        is_reasoning_model = bool(_REASONING_RE.match(self.model))

        kwargs: dict = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
        }
        # max_tokens <= 0 means "no explicit cap" — omit the param so the model
        # uses its own default ceiling (useful to measure natural consumption and
        # to avoid truncating reasoning-model output).
        if is_reasoning_model:
            # Reasoning models: no temperature support, use max_completion_tokens.
            if max_tokens and max_tokens > 0:
                kwargs["max_completion_tokens"] = max_tokens
        else:
            if max_tokens and max_tokens > 0:
                kwargs["max_tokens"] = max_tokens
            kwargs["temperature"] = temperature

        response = self.client.chat.completions.create(**kwargs)
        content = response.choices[0].message.content or ""
        usage = response.usage
        self._record_call(
            prompt, content,
            usage.prompt_tokens if usage else None,
            usage.completion_tokens if usage else None,
        )
        return content
