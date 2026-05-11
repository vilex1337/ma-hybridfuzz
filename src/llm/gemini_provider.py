"""Google Gemini backend for the MA-HybridFuzz LLM abstraction."""

import logging
import os

from google import genai  # type: ignore[import-untyped]
from google.genai import types  # type: ignore[import-untyped]

from llm.provider import LLMProvider

logger = logging.getLogger("llm.gemini")


class GeminiProvider(LLMProvider):
    """Wrapper around google.genai.Client.models.generate_content."""

    def __init__(self, model: str):
        api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
        if not api_key:
            raise RuntimeError(
                "GEMINI_API_KEY (or GOOGLE_API_KEY) is not set. "
                "Export it or add it to .env."
            )
        self.model = model
        self.client = genai.Client(api_key=api_key)

    def generate(
        self,
        prompt: str,
        max_tokens: int = 4096,
        temperature: float = 0.3,
    ) -> str:
        response = self.client.models.generate_content(
            model=self.model,
            contents=prompt,
            config=types.GenerateContentConfig(
                max_output_tokens=max_tokens,
                temperature=temperature,
            ),
        )
        return response.text or ""
