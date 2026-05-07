"""Self-hosted LLM backend (FastAPI server from inference/*.ipynb).

Targets the /chat endpoint (instruct/chat-template) by default.
Set use_chat=False in the config to fall back to /generate (raw completion).

Configuration:
    llm:
      provider: "self_hosted"
      model: "qwen2.5-coder-14b"   # label only, not sent to the server
      base_url: "https://<ngrok-id>.ngrok-free.app"
      max_tokens: 512
      temperature: 0.7

Environment variable fallback:
    SELF_HOSTED_BASE_URL   used when config['llm']['base_url'] is absent
"""

import logging

import requests

from llm.provider import LLMProvider

logger = logging.getLogger("llm.self_hosted")

_DEFAULT_TIMEOUT = 600  # seconds


class SelfHostedProvider(LLMProvider):
    """Calls the FastAPI inference server defined in inference/*.ipynb."""

    def __init__(self, model: str, base_url: str, use_chat: bool = True, timeout: int = _DEFAULT_TIMEOUT):
        if not base_url:
            raise RuntimeError(
                "Self-hosted provider requires a base_url. "
                "Set config['llm']['base_url'] or SELF_HOSTED_BASE_URL."
            )
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.use_chat = use_chat
        self.timeout = timeout

    def generate(
        self,
        prompt: str,
        max_tokens: int = 512,
        temperature: float = 0.7,
    ) -> str:
        if self.use_chat:
            return self._chat(prompt, max_tokens, temperature)
        return self._generate(prompt, max_tokens, temperature)

    def _chat(self, prompt: str, max_tokens: int, temperature: float) -> str:
        payload = {
            "messages": [{"role": "user", "content": prompt}],
            "max_new_tokens": max_tokens,
            "temperature": temperature,
            "do_sample": temperature > 0,
        }
        resp = requests.post(
            f"{self.base_url}/chat",
            json=payload,
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json().get("content", "")

    def _generate(self, prompt: str, max_tokens: int, temperature: float) -> str:
        payload = {
            "prompt": prompt,
            "max_new_tokens": max_tokens,
            "temperature": temperature,
            "do_sample": temperature > 0,
        }
        resp = requests.post(
            f"{self.base_url}/generate",
            json=payload,
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json().get("generated_text", "")
