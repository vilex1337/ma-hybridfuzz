"""
CLI Proxy API backend — OpenAI-compatible local proxy (e.g. cliproxyapi).

Configuration:
    llm:
      provider: "cliproxy"
      model: "gpt-5.4"           # any model exposed by the proxy
      base_url: "http://127.0.0.1:8317/v1"
      api_key: "sk-..."          # or set CLIPROXY_API_KEY env var
      max_tokens: 4096
      temperature: 0.3
"""

import logging

from openai import OpenAI

from llm.provider import LLMProvider

logger = logging.getLogger("llm.cliproxy")


class ClipProxyProvider(LLMProvider):
    def __init__(self, model: str, base_url: str, api_key: str):
        self.model = model
        self.client = OpenAI(base_url=base_url, api_key=api_key)

    def generate(
        self,
        prompt: str,
        max_tokens: int = 4096,
        temperature: float = 0.3,
    ) -> str:
        kwargs: dict = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": temperature,
        }
        # max_tokens <= 0 ⇒ omit the cap (model default; avoids truncating
        # reasoning models like deepseek-reasoner and measures real usage).
        if max_tokens and max_tokens > 0:
            kwargs["max_tokens"] = max_tokens
        response = self.client.chat.completions.create(**kwargs)
        content = response.choices[0].message.content or ""
        usage = response.usage
        self._record_call(
            prompt, content,
            usage.prompt_tokens if usage else None,
            usage.completion_tokens if usage else None,
        )
        return content
