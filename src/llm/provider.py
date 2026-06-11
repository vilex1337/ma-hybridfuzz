"""
LLM Provider abstraction — supports Anthropic, OpenAI (Codex), Google Gemini, self-hosted, and cliproxy.

All agents interact with LLMs through this unified interface. To switch providers,
change the `llm.provider` and `llm.model` fields in the config; no code changes required.

Configuration:
    llm:
      provider: "anthropic"        # anthropic | openai | gemini | self_hosted | cliproxy
      model: "claude-sonnet-4-6"
      max_tokens: 4096
      temperature: 0.3

Environment variables (only the one matching the chosen provider is required):
    ANTHROPIC_API_KEY   for provider="anthropic"
    OPENAI_API_KEY      for provider="openai"     (a.k.a. Codex key)
    GEMINI_API_KEY      for provider="gemini"     (or GOOGLE_API_KEY)
    CLIPROXY_API_KEY    for provider="cliproxy"   (or set config['llm']['api_key'])
    CLIPROXY_BASE_URL   for provider="cliproxy"   (default: http://127.0.0.1:8317/v1)
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod

from config import AppConfig

logger = logging.getLogger("llm.provider")


class LLMProvider(ABC):
    """Unified stateless-completion interface for all supported providers."""

    model: str

    # Accumulated usage counters — incremented by each concrete provider's generate().
    input_tokens: int = 0
    output_tokens: int = 0
    request_count: int = 0

    @abstractmethod
    def generate(
        self,
        prompt: str,
        max_tokens: int = 4096,
        temperature: float = 0.3,
    ) -> str:
        """Send a single-turn prompt and return the model's text response."""

    def _add_usage(self, input_tokens: int, output_tokens: int) -> None:
        self.input_tokens += input_tokens
        self.output_tokens += output_tokens
        self.request_count += 1

    def usage_summary(self) -> dict:
        return {
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "request_count": self.request_count,
        }


# Known-good model IDs per provider. Users may specify other IDs at their own risk;
# unknown IDs trigger a warning but still go through to the SDK.
SUPPORTED_MODELS: dict[str, set[str]] = {
    "anthropic": {
        "claude-opus-4-6",
        "claude-sonnet-4-6",
        "claude-haiku-4-5",
        "claude-sonnet-4-5",
        "claude-opus-4-5",
    },
    "openai": {
        "gpt-5",
        "gpt-5-mini",
        "gpt-4o",
        "gpt-4o-mini",
        "o1",
        "o1-mini",
    },
    "gemini": {
        "gemini-2.5-pro",
        "gemini-2.5-flash",
        "gemini-2.0-flash",
        "gemini-2.0-flash-lite",
        "gemini-1.5-pro",
        "gemini-1.5-flash",
    },
    # Any model ID is accepted for self-hosted; the set is intentionally empty.
    "self_hosted": set(),
    # Any model ID is accepted for cliproxy; the set is intentionally empty.
    "cliproxy": set(),
}


def create_provider(config: AppConfig) -> LLMProvider:
    """Instantiate the provider described by the project config.

    The config's ``llm.provider`` selects the backend and ``llm.model`` picks the
    model ID. Unknown model IDs are accepted with a warning so that newer models
    can be used without code changes.
    """
    llm = config.llm
    provider_name = llm.provider
    model = llm.model

    if provider_name not in SUPPORTED_MODELS:
        raise ValueError(
            f"Unsupported LLM provider: '{provider_name}'. "
            f"Expected one of: {sorted(SUPPORTED_MODELS)}"
        )

    known = SUPPORTED_MODELS[provider_name]
    if known and model not in known:
        logger.warning(
            "Model '%s' is not in the known list for provider '%s'. Proceeding anyway.",
            model, provider_name,
        )

    if provider_name == "anthropic":
        from llm.anthropic_provider import AnthropicProvider
        return AnthropicProvider(model=model)
    if provider_name == "openai":
        from llm.openai_provider import OpenAIProvider
        return OpenAIProvider(model=model)
    if provider_name == "gemini":
        from llm.gemini_provider import GeminiProvider
        return GeminiProvider(model=model)
    if provider_name == "cliproxy":
        import os
        from llm.cliproxy_provider import ClipProxyProvider
        base_url = llm.base_url or os.getenv("CLIPROXY_BASE_URL", "http://127.0.0.1:8317/v1")
        api_key = llm.api_key or os.getenv("CLIPROXY_API_KEY", "")
        if not api_key:
            raise RuntimeError(
                "cliproxy provider requires an API key. "
                "Set config.llm.api_key or CLIPROXY_API_KEY."
            )
        return ClipProxyProvider(model=model, base_url=base_url, api_key=api_key)
    if provider_name == "self_hosted":
        import os
        from llm.self_hosted_provider import SelfHostedProvider
        base_url = llm.base_url or os.getenv("SELF_HOSTED_BASE_URL", "")
        sid = (
            config.inference_session_id
            or llm.sid
            or os.getenv("MA_HYBRIDFUZZ_SID", "default")
        )
        return SelfHostedProvider(
            model=model,
            base_url=base_url,
            use_chat=llm.use_chat,
            timeout=llm.timeout,
            sid=sid,
        )

    raise ValueError(f"Unhandled provider: {provider_name}")
