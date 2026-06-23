"""
Typed configuration dataclasses for MA-HybridFuzz.

All components import their needed config from here instead of accessing
the raw YAML dict directly.  The top-level AppConfig.from_dict() is the
single entry point: call it once in Orchestrator and pass it everywhere.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _env(*names: str) -> str | None:
    """Return the first non-empty environment variable among *names*."""
    for name in names:
        val = os.getenv(name)
        if val:
            return val
    return None


# ---------------------------------------------------------------------------
# Per-section dataclasses
# ---------------------------------------------------------------------------

@dataclass
class LLMConfig:
    provider: str
    model: str
    max_tokens: int
    temperature: float
    base_url: str = ""
    api_key: str = ""
    timeout: int = 300
    use_chat: bool = True
    sid: str = ""

    @classmethod
    def from_dict(cls, raw: dict) -> "LLMConfig":
        # Environment overrides let one config set drive every fuzzer variant
        # (deepseek / chatgpt / ...) without editing per-CVE YAML files. The
        # benchmark script injects MA_LLM_* per fuzzer. See docs/BENCHMARK_VM.md.
        provider = _env("MA_LLM_PROVIDER") or raw.get("provider", "anthropic")
        return cls(
            provider=provider.lower(),
            model=_env("MA_LLM_MODEL") or raw["model"],
            # Reasoning models (o4-mini, ...) spend part of the budget on hidden
            # reasoning tokens, so a larger max may be needed for a usable answer.
            max_tokens=int(_env("MA_LLM_MAX_TOKENS") or raw["max_tokens"]),
            temperature=float(raw.get("temperature", 0.2)),
            base_url=_env("MA_LLM_BASE_URL") or raw.get("base_url", ""),
            api_key=_env("MA_LLM_API_KEY") or raw.get("api_key", ""),
            timeout=int(raw.get("timeout", 300)),
            use_chat=bool(raw.get("use_chat", True)),
            sid=raw.get("sid", ""),
        )


@dataclass
class TargetConfig:
    binary: str
    source_dir: str
    target_function: str
    bug_type: str
    args: list[str] = field(default_factory=lambda: ["@@"])
    build_dir: str = ""
    program_usage: str = ""
    bug_report: str = ""
    fcc: list[str] = field(default_factory=list)
    coverage_binary: str = ""
    coverage_compile_flags: list[str] = field(default_factory=list)
    ir_build_dir: str = ""
    ir_cc: str = "clang"
    ir_cxx: str = "clang++"
    ir_compile_flags: list[str] = field(default_factory=list)
    ir_build_timeout: int = 300
    entry_points: list[str] = field(default_factory=list)
    magma_bug_id: str = ""

    @classmethod
    def from_dict(cls, raw: dict) -> "TargetConfig":
        return cls(
            binary=raw["binary"],
            source_dir=raw["source_dir"],
            target_function=raw["target_function"],
            bug_type=raw["bug_type"],
            args=raw.get("args", ["@@"]),
            build_dir=raw.get("build_dir", raw.get("source_dir", "")),
            program_usage=raw.get("program_usage", ""),
            bug_report=raw.get("bug_report", ""),
            fcc=raw.get("fcc", []),
            coverage_binary=raw.get("coverage_binary", ""),
            coverage_compile_flags=raw.get("coverage_compile_flags", []),
            magma_bug_id=raw.get("magma_bug_id", ""),
            ir_build_dir=raw.get("ir_build_dir", ""),
            ir_cc=raw.get("ir_cc", "clang"),
            ir_cxx=raw.get("ir_cxx", "clang++"),
            ir_compile_flags=raw.get("ir_compile_flags", []),
            ir_build_timeout=int(raw.get("ir_build_timeout", 300)),
            entry_points=raw.get("entry_points", []),
        )


@dataclass
class FuzzerConfig:
    timeout: int
    exec_timeout: int
    memory_limit: int
    use_asan: bool
    use_ubsan: bool
    engine: str = "afl++"
    seed_count: int = 5
    use_custom_mutator: bool = True

    @classmethod
    def from_dict(cls, raw: dict) -> "FuzzerConfig":
        # MA_FUZZER_TIMEOUT lets the benchmark script shorten runs for smoke
        # tests without touching the 6h (21600s) value in the configs.
        timeout = int(_env("MA_FUZZER_TIMEOUT") or raw["timeout"])
        return cls(
            engine=raw.get("engine", "afl++"),
            timeout=timeout,
            exec_timeout=int(raw["exec_timeout"]),
            memory_limit=int(raw["memory_limit"]),
            seed_count=int(raw.get("seed_count", 5)),
            use_asan=bool(raw.get("use_asan", True)),
            use_ubsan=bool(raw.get("use_ubsan", False)),
            use_custom_mutator=bool(raw.get("use_custom_mutator", True)),
        )


@dataclass
class PathsConfig:
    corpus: str
    crashes: str
    mutators: str
    distance_cache: str
    coverage: str
    logs: str
    memory: str = "/workspace/memory"

    @classmethod
    def from_dict(cls, raw: dict) -> "PathsConfig":
        return cls(
            corpus=raw["corpus"],
            crashes=raw["crashes"],
            mutators=raw["mutators"],
            distance_cache=raw["distance_cache"],
            coverage=raw["coverage"],
            logs=raw["logs"],
            memory=raw.get("memory", "/workspace/memory"),
        )


@dataclass
class AttentionConfig:
    enabled: bool = True
    server_url: str = ""
    sid: str = ""

    @classmethod
    def from_dict(cls, attention_raw: dict, attention_distance_raw: dict) -> "AttentionConfig":
        enabled = bool(attention_raw.get("enabled", True))
        env_enabled = _env("MA_ATTENTION_ENABLED")
        if env_enabled is not None:
            enabled = env_enabled.strip().lower() in ("1", "true", "yes", "on")
        # LineVul runs as a server on the VM host (outside Docker) to keep the
        # fuzzer image light; run_benchmark.sh sets MA_LINEVUL_SERVER_URL to
        # http://host.docker.internal:<port>. The stale ngrok URLs committed in
        # configs/magma/**.yml are intentionally ignored. With no URL set, the
        # scorer would try the in-process model (absent in the slim image) and
        # then fall back to uniform attention scores.
        return cls(
            enabled=enabled,
            server_url=_env("MA_LINEVUL_SERVER_URL") or "",
            sid=attention_distance_raw.get("sid", ""),
        )


@dataclass
class SchedulerConfig:
    attention_weight: float = 0.6
    coverage_weight: float = 0.3
    speed_weight: float = 0.1

    @classmethod
    def from_dict(cls, raw: dict) -> "SchedulerConfig":
        return cls(
            attention_weight=float(raw.get("attention_weight", 0.6)),
            coverage_weight=float(raw.get("coverage_weight", 0.3)),
            speed_weight=float(raw.get("speed_weight", 0.1)),
        )


@dataclass
class ReassessmentConfig:
    plateau_threshold: int = 300
    reassessment_coverage_rate: float = 0.05
    max_reassessments: int = 5

    @classmethod
    def from_dict(cls, raw: dict) -> "ReassessmentConfig":
        return cls(
            plateau_threshold=int(raw.get("plateau_threshold", 300)),
            reassessment_coverage_rate=float(raw.get("reassessment_coverage_rate", 0.05)),
            max_reassessments=int(raw.get("max_reassessments", 5)),
        )


@dataclass
class SessionConfig:
    id: str = ""

    @classmethod
    def from_dict(cls, raw: dict) -> "SessionConfig":
        return cls(id=raw.get("id", ""))


@dataclass
class LoggingConfig:
    verbosity: int = 1

    @classmethod
    def from_dict(cls, raw: dict) -> "LoggingConfig":
        return cls(verbosity=int(raw.get("verbosity", 1)))


@dataclass
class SeedGeneratorConfig:
    code_retries: int = 3

    @classmethod
    def from_dict(cls, raw: dict) -> "SeedGeneratorConfig":
        return cls(code_retries=int(raw.get("code_retries", 3)))


@dataclass
class MutatorGeneratorConfig:
    compile_retries: int = 3

    @classmethod
    def from_dict(cls, raw: dict) -> "MutatorGeneratorConfig":
        return cls(compile_retries=int(raw.get("compile_retries", 3)))


# ---------------------------------------------------------------------------
# Top-level config
# ---------------------------------------------------------------------------

@dataclass
class AppConfig:
    llm: LLMConfig
    target: TargetConfig
    fuzzer: FuzzerConfig
    paths: PathsConfig
    attention: AttentionConfig
    scheduler: SchedulerConfig
    reassessment: ReassessmentConfig
    session: SessionConfig
    logging_cfg: LoggingConfig
    seed_generator: SeedGeneratorConfig
    mutator_generator: MutatorGeneratorConfig
    inference_session_id: str = ""

    @classmethod
    def from_dict(cls, raw: dict) -> "AppConfig":
        return cls(
            llm=LLMConfig.from_dict(raw.get("llm", {})),
            target=TargetConfig.from_dict(raw.get("target", {})),
            fuzzer=FuzzerConfig.from_dict(raw.get("fuzzer", {})),
            paths=PathsConfig.from_dict(raw.get("paths", {})),
            attention=AttentionConfig.from_dict(
                raw.get("attention", {}),
                raw.get("attention_distance", {}),
            ),
            scheduler=SchedulerConfig.from_dict(raw.get("scheduler", {})),
            reassessment=ReassessmentConfig.from_dict(raw.get("reassessment", {})),
            session=SessionConfig.from_dict(raw.get("session", {})),
            logging_cfg=LoggingConfig.from_dict(raw.get("logging", {})),
            seed_generator=SeedGeneratorConfig.from_dict(raw.get("seed_generator", {})),
            mutator_generator=MutatorGeneratorConfig.from_dict(raw.get("mutator_generator", {})),
            inference_session_id=raw.get("inference_session_id", ""),
        )
