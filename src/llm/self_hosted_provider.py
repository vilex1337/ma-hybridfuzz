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
import time

import requests

from llm.provider import LLMProvider

logger = logging.getLogger("llm.self_hosted")

_DEFAULT_TIMEOUT = 600  # seconds
_RETRY_BASE = 5   # seconds; delay = base * 2^attempt → 5, 10, 20, 40 s
_MAX_RETRIES = 4


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

    def _post_with_retry(self, url: str, payload: dict) -> requests.Response:
        """POST with exponential-of-2 retry on temporary errors (5xx, connection, timeout)."""
        for attempt in range(_MAX_RETRIES + 1):
            try:
                resp = requests.post(url, json=payload, timeout=self.timeout)
                resp.raise_for_status()
                return resp
            except Exception as exc:
                temporary = (
                    isinstance(exc, requests.exceptions.HTTPError)
                    and exc.response is not None
                    and exc.response.status_code >= 500
                ) or isinstance(exc, (requests.exceptions.ConnectionError,
                                      requests.exceptions.Timeout))
                if attempt == _MAX_RETRIES or not temporary:
                    raise
                delay = _RETRY_BASE * (2 ** attempt)
                logger.warning(
                    "LLM request failed (%s); retry %d/%d in %ds",
                    exc, attempt + 1, _MAX_RETRIES, delay,
                )
                time.sleep(delay)
        raise RuntimeError("unreachable")  # satisfies type checkers

    def _chat(self, prompt: str, max_tokens: int, temperature: float) -> str:
        payload = {
            "messages": [{"role": "user", "content": prompt}],
            "max_new_tokens": max_tokens,
            "temperature": temperature,
            "do_sample": temperature > 0,
        }
        resp = self._post_with_retry(f"{self.base_url}/chat", payload)
        return resp.json().get("content", "")

    def _generate(self, prompt: str, max_tokens: int, temperature: float) -> str:
        payload = {
            "prompt": prompt,
            "max_new_tokens": max_tokens,
            "temperature": temperature,
            "do_sample": temperature > 0,
        }
        resp = self._post_with_retry(f"{self.base_url}/generate", payload)
        return resp.json().get("generated_text", "")
