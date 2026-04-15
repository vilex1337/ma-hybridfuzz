# MA-HybridFuzz

**Multi-Agent Hybrid Directed Fuzzing with On-Demand LLM Guidance for Efficient PoV Generation**

A directed fuzzing framework that combines LLM-generated seeds and mutators
(Gap 3) with attention-based semantic distance guidance (Gap 1) to trigger
vulnerabilities faster than classic directed fuzzers, while keeping the hot
fuzzing loop native (no LLM-per-input overhead).

## Pipeline Overview

```
 ┌──────────────────┐    ┌───────────────────────┐    ┌────────────────────┐
 │ Phase 1          │    │ Phase 2               │    │ Phase 3            │
 │ Pre-phase (LLM)  │───▶│ Fuzzing Loop (native) │───▶│ Reassessment       │
 │                  │    │                       │    │ (on plateau only)  │
 │ 3–6 LLM calls    │    │ 0 LLM calls           │    │ 2 LLM calls each   │
 └──────────────────┘    └───────────────────────┘    └────────────────────┘
     │                         │                          │
     ▼                         ▼                          ▼
 seeds, mutators,         AFL++ + custom mutator      new seeds hot-added
 attention distance       + attention scheduler        to AFL++ corpus
 matrix                   + ASAN crash oracle          + mutator updates
```

- **Phase 1 — Pre-phase:** LLM extracts bug info, summarises functions, computes
  attention-distance matrix, generates reachable seeds along the function call
  chain, and builds bug-specific custom mutators.
- **Phase 2 — Fuzzing loop:** AFL++ runs at native speed with the pre-computed
  artefacts; coverage is snapshotted every 10s.
- **Phase 3 — Reassessment:** Triggered only on coverage plateaus. Two LLM calls
  diagnose the stall and inject new seeds/mutators.

## Quick Start (Gemini free tier)

```bash
# 1. Clone and install
git clone https://github.com/vilesport/ma-hybridfuzz.git
cd ma-hybridfuzz
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 2. Configure API key (Gemini is free → https://aistudio.google.com/apikey)
cp .env.example .env
echo "GEMINI_API_KEY=AIza..." >> .env

# 3. Edit configs/default.yml — point `target.*` at your binary and source

# 4. Run the full pipeline
./scripts/run.sh configs/default.yml
```

For the full walkthrough (including OpenAI/Anthropic, Docker, troubleshooting,
inspecting crashes), see **[docs/SETUP.md](docs/SETUP.md)**.

## Supported LLM Providers

Swap providers via the `llm.provider` + `llm.model` fields in the config. The
same code path handles all three — no code changes required.

| Provider | Env var | Free tier | Example models |
|----------|---------|-----------|-----------------|
| `anthropic` | `ANTHROPIC_API_KEY` | No | `claude-sonnet-4-6`, `claude-opus-4-6`, `claude-haiku-4-5` |
| `openai` | `OPENAI_API_KEY` | No (ChatGPT Plus ≠ API credit) | `gpt-5`, `gpt-5-mini`, `gpt-4o`, `gpt-4o-mini`, `o1-mini` |
| `gemini` | `GEMINI_API_KEY` | **Yes** (generous) | `gemini-2.5-pro`, `gemini-2.5-flash`, `gemini-2.0-flash` |

## Configuration

Minimum `configs/default.yml`:

```yaml
target:
  binary: "./build/vuln"
  source_dir: "./src"
  target_function: "parse_payload"
  bug_type: "heap-buffer-overflow"
  bug_report: "Description of the CVE or bug..."
  program_usage: "./vuln <input_file>"
  fcc: ["main", "parse_header", "parse_payload"]   # optional

llm:
  provider: "gemini"
  model: "gemini-2.5-flash"
  max_tokens: 4096
  temperature: 0.3
```

## Project Structure

```
.
├── configs/                      # YAML config files
├── docker/                       # Dockerfile.fuzzer (AFL++ + Python)
├── docs/
│   ├── ARCHITECTURE.md           # detailed system design
│   └── SETUP.md                  # complete setup & run guide
├── scripts/                      # setup.sh, run.sh
├── src/
│   ├── orchestrator.py           # pipeline coordinator
│   ├── llm/                      # provider abstraction (anthropic/openai/gemini)
│   │   ├── provider.py
│   │   ├── anthropic_provider.py
│   │   ├── openai_provider.py
│   │   └── gemini_provider.py
│   ├── pre_phase/                # Phase 1 + Phase 3 agents (LLM)
│   │   ├── base_agent.py
│   │   ├── reasoning_agent.py
│   │   ├── reassessment_agent.py
│   │   ├── seed_generator.py
│   │   ├── mutator_generator.py
│   │   ├── attention_computer.py
│   │   └── persistent_memory.py
│   └── fuzzing/                  # Phase 2 (native AFL++)
│       ├── afl_runner.py
│       └── scheduler.py
├── workspace/                    # runtime data (gitignored)
│   ├── corpus/  crashes/  mutators/  distance_cache/
│   ├── coverage/  logs/  memory/  instrumented/
├── docker-compose.yml
├── requirements.txt
└── .env.example
```

## Research Gaps Addressed

| Gap | Description | Implementation |
|-----|-------------|----------------|
| Gap 1 | Attention distance as a semantic-guidance metric | `src/pre_phase/attention_computer.py`, `src/fuzzing/scheduler.py` |
| Gap 3 | LLM-pre-generated reachable seeds & bug-specific mutators | `src/pre_phase/seed_generator.py`, `src/pre_phase/mutator_generator.py`, `src/pre_phase/reasoning_agent.py` |

Reference papers live in `paper/` (Attention Distance, PBFuzz, RandLuzz).

## Requirements

- Python 3.10+
- Either **AFL++** installed locally, **or** Docker + Docker Compose
- One of: Anthropic / OpenAI / Gemini API key

## Documentation

- **[docs/SETUP.md](docs/SETUP.md)** — full setup + run guide with troubleshooting
- **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** — detailed system architecture
