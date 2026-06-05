"""
LLM Provider abstraction — supports Anthropic, OpenAI (Codex), and Google Gemini.

All agents interact with LLMs through this unified interface. To switch providers,
change the `llm.provider` and `llm.model` fields in the config; no code changes required.

Configuration:
    llm:
      provider: "anthropic"        # anthropic | openai | gemini
      model: "claude-sonnet-4-6"
      max_tokens: 4096
      temperature: 0.3

Environment variables (only the one matching the chosen provider is required):
    ANTHROPIC_API_KEY   for provider="anthropic"
    OPENAI_API_KEY      for provider="openai"     (a.k.a. Codex key)
    GEMINI_API_KEY      for provider="gemini"     (or GOOGLE_API_KEY)
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod

logger = logging.getLogger("llm.provider")


class LLMProvider(ABC):
    """Unified stateless-completion interface for all supported providers."""

    model: str

    @abstractmethod
    def generate(
        self,
        prompt: str,
        max_tokens: int = 4096,
        temperature: float = 0.3,
    ) -> str:
        """Send a single-turn prompt and return the model's text response."""


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
}


def create_provider(config: dict) -> LLMProvider:
    """Instantiate the provider described by the project config.

    The config's ``llm.provider`` selects the backend and ``llm.model`` picks the
    model ID. Unknown model IDs are accepted with a warning so that newer models
    can be used without code changes.
    """
    llm_config = config.get("llm", {})
    provider_name = llm_config.get("provider", "anthropic").lower()
    model = llm_config.get("model")
    if not model:
        raise ValueError("config['llm']['model'] is required")

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
    if provider_name == "self_hosted":
        import os
        from llm.self_hosted_provider import SelfHostedProvider
        base_url = llm_config.get("base_url") or os.getenv("SELF_HOSTED_BASE_URL", "")
        use_chat = llm_config.get("use_chat", True)
        timeout = int(llm_config.get("timeout", 300))
        sid = (
            config.get("inference_session_id")
            or llm_config.get("sid")
            or os.getenv("MA_HYBRIDFUZZ_SID", "default")
        )
        return SelfHostedProvider(
            model=model,
            base_url=base_url,
            use_chat=use_chat,
            timeout=timeout,
            sid=sid,
        )

    raise ValueError(f"Unhandled provider: {provider_name}")
