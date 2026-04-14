# MA-HybridFuzz — Setup & Full Run Guide

This guide walks through setting up MA-HybridFuzz and running the full directed
fuzzing pipeline end-to-end, from installing dependencies to inspecting crash
results.

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Clone & Install](#2-clone--install)
3. [Choose an LLM Provider](#3-choose-an-llm-provider)
4. [Prepare Your Target](#4-prepare-your-target)
5. [Configure](#5-configure)
6. [Run the Full Pipeline](#6-run-the-full-pipeline)
7. [Inspect Results](#7-inspect-results)
8. [Troubleshooting](#8-troubleshooting)

---

## 1. Prerequisites

**Required** (all modes)
- Git
- Python 3.10+
- An API key from one of: Anthropic, OpenAI, or Google Gemini

**For Docker mode (recommended)**
- Docker 20.10+
- Docker Compose v2

**For local mode (no Docker)**
- AFL++ (`afl-fuzz`, `afl-clang-fast`) — https://github.com/AFLplusplus/AFLplusplus
- Clang with AddressSanitizer support

---

## 2. Clone & Install

```bash
git clone https://github.com/vilesport/ma-hybridfuzz.git
cd ma-hybridfuzz

# Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies (covers all three LLM providers)
pip install -r requirements.txt
```

---

## 3. Choose an LLM Provider

The framework supports three providers via a unified abstraction in `src/llm/`.
Pick **one** provider, set its API key, and point the config at it. You do not
need keys for providers you are not using.

| Provider | Env var | Free tier | Suggested model |
|----------|---------|-----------|------------------|
| `anthropic` | `ANTHROPIC_API_KEY` | No (paid) | `claude-sonnet-4-6` |
| `openai` | `OPENAI_API_KEY` | No (paid) | `gpt-4o-mini` |
| `gemini` | `GEMINI_API_KEY` | **Yes** (generous) | `gemini-2.5-flash` |

### 3.1 Get the key

- **Anthropic:** https://console.anthropic.com/settings/keys
- **OpenAI:** https://platform.openai.com/api-keys (requires funded billing)
- **Gemini:** https://aistudio.google.com/apikey (free tier, Google account only)

### 3.2 Save the key

Copy `.env.example` to `.env` and fill in the matching field:

```bash
cp .env.example .env
chmod 600 .env       # make sure only you can read it
```

Example for Gemini:

```
ANTHROPIC_API_KEY=
OPENAI_API_KEY=
GEMINI_API_KEY=AIza...
```

> **Switching providers later** requires two steps:
> 1. Set the correct env var in `.env`
> 2. Update `llm.provider` **and** `llm.model` in the config file.
>
> Just changing the env var is not enough — the config selects the backend.

---

## 4. Prepare Your Target

A target consists of:
- **Source code** (C/C++ preferred — AFL++ instrumentation works via `afl-clang-fast`)
- **Target function** — the function you want to reach (vulnerability site)
- **Bug report / CVE description** — natural-language description of the bug
- **Program usage** — how the binary is invoked (e.g. `./vuln <input_file>`)

### Minimum file layout

```
my_target/
├── src/
│   ├── main.c
│   └── vuln.c            # contains the target function
├── bug_report.txt        # CVE description or free-form bug notes
└── README.md             # optional: notes on how to build
```

### Example: the bundled test target

An end-to-end example lives in `test_dir/` (gitignored for repos; see
`test_dir/TUTORIAL.md` on your local checkout). It provides a C program with
a heap-buffer-overflow in `parse_payload()` that you can fuzz without any
external dependencies.

---

## 5. Configure

Create a config file (copy `configs/default.yml` or write your own):

```yaml
target:
  binary: "./my_target/build/vuln"                # path to the instrumented binary
  source_dir: "./my_target/src"                    # path to source code
  target_function: "parse_payload"                 # function to reach
  bug_type: "heap-buffer-overflow"                 # e.g. heap-buffer-overflow, use-after-free
  bug_report: |
    Heap buffer overflow in parse_payload() triggered when ...
  program_usage: "./vuln <input_file>"
  fcc:                                             # optional: function call chain
    - "main"
    - "parse_header"
    - "parse_payload"

llm:
  provider: "gemini"
  model: "gemini-2.5-flash"
  max_tokens: 4096
  temperature: 0.3

fuzzer:
  engine: "afl++"
  timeout: 3600            # total fuzzing seconds (1 hour)
  exec_timeout: 1000       # per-execution timeout in ms
  memory_limit: 256        # MB
  seed_count: 20           # LLM-generated seeds
  use_asan: true
  use_ubsan: false

scheduler:
  attention_weight: 0.6    # attention distance weight
  coverage_weight: 0.3     # coverage novelty weight
  speed_weight: 0.1        # exec-speed weight

reassessment:
  plateau_threshold: 300   # seconds without new coverage → trigger LLM reassessment
  max_reassessments: 5     # cap on LLM reassessment calls per run

paths:
  corpus: "/workspace/corpus"
  crashes: "/workspace/crashes"
  mutators: "/workspace/mutators"
  distance_cache: "/workspace/distance_cache"
  coverage: "/workspace/coverage"
  logs: "/workspace/logs"
  memory: "/workspace/memory"
```

The `fcc` field is **optional but valuable**. If provided, the ReasoningAgent
uses RANDLUZZ §3.3.2 (reason-along-FCC) to iteratively refine seeds from
program entry toward the target. If omitted, it falls back to §3.3.3 (reason
based on functionality) using attention-distance neighbors.

---

## 6. Run the Full Pipeline

### Option A — Docker (recommended)

```bash
./scripts/setup.sh                         # builds the Docker image
./scripts/run.sh configs/default.yml       # runs the full pipeline
```

### Option B — Local (need AFL++ installed)

```bash
source .venv/bin/activate
mkdir -p workspace/{corpus,crashes,mutators,distance_cache,coverage,logs,memory}
PYTHONPATH=src python3 src/orchestrator.py -c configs/default.yml
```

### What happens in the run

The orchestrator executes three phases automatically. Typical log output:

```text
=== MA-HybridFuzz Starting ===
--- Phase 1: Pre-phase (LLM) ---
[Pre-phase SA] Computing attention distance matrix...
[Pre-phase SA] Attention distance matrix cached
[Pre-phase] Extracting bug information from report...
[Pre-phase] Bug info: function=parse_payload type=heap-buffer-overflow
[Pre-phase] Generating function summary for 'parse_payload'...
[Pre-phase Opt] Generating preliminary seed...
[Pre-phase Opt] Reasoning along FCC (2 hops)...
[Pre-phase Opt] Writing 8 reachable seeds to corpus...
[Pre-phase Mutator] Generating bug-specific mutators...
[Pre-phase Mutator] Generated 4 custom mutators

--- Phase 2: Fuzzing Loop ---
[Fuzzing] Instrumenting target binary...
[Fuzzing] Starting AFL++ with attention-guided scheduling...
[Fuzzing] 10s elapsed  | coverage: 42  | crashes: 0 | execs: 2134/s
[Fuzzing] 20s elapsed  | coverage: 58  | crashes: 0 | execs: 2210/s
...
[Fuzzing] 310s elapsed | coverage: 58  | crashes: 0 | execs: 2187/s

--- Phase 3 (on-demand) ---
[Reassessment #1] Plateau detected (305s). Activating LLM...
[Reassessment #1] Added 5 new seeds to corpus
[Reassessment #1] Generated 3 updated mutators

[Fuzzing] 320s elapsed | coverage: 61  | crashes: 1 | execs: 2201/s
...
=== MA-HybridFuzz Complete ===
=== Results ===
Total crashes found: 3
```

### Phase breakdown

**Phase 1 — Pre-phase (LLM-driven, ~30–60s, 3–6 LLM calls)**

| Step | Purpose | Output |
|------|---------|--------|
| Attention distance matrix | Compute semantic distance between every function and the target (Gap 1) | `distance_cache/attention_distances.{pkl,json}` |
| Bug info extraction | Parse the bug report into structured data | in-memory `bug_info` dict |
| Function summary | Summarize target + FCC intermediates for later reasoning | in-memory `target_summary` dict |
| Preliminary seed | Produce one broad seed from program usage + summary | `corpus/` |
| Seeds along FCC (or functionality-based) | Iteratively refine seeds along the call chain | `corpus/` |
| Bug-specific mutators | Two-stage: Bug Analysis → mutator code | `mutators/mutator_*.py` |

**Phase 2 — Fuzzing loop (native AFL++, no LLM)**

The orchestrator launches `afl-fuzz` with:
- Pre-generated corpus as initial seeds
- Custom Python mutator loaded via `AFL_PYTHON_MODULE`
- Power schedule `exploit` when a distance matrix exists, else `fast`
- AddressSanitizer (if `use_asan: true`) to catch memory-safety bugs

The orchestrator polls `fuzzer_stats` every 10s and snapshots coverage to
`workspace/memory/` (persistent memory). **No LLM calls happen in this loop.**

**Phase 3 — On-demand reassessment (2 LLM calls per activation)**

Triggered when no new coverage has been found for `plateau_threshold` seconds
(default 300). Two LLM calls:

1. `diagnose()` — analyse current AFL state and explain why the fuzzer is stuck
2. `generate_recovery_plan()` — return new seeds and (optionally) updated mutators

New seeds are dropped into `corpus/` and AFL++ picks them up automatically on
its next queue refresh. Capped at `max_reassessments` activations to bound the
total LLM cost.

---

## 7. Inspect Results

### Crashes

AFL++ writes crash-triggering inputs to `workspace/crashes/default/crashes/`:

```bash
ls workspace/crashes/default/crashes/
# id:000000,sig:06,src:000003,time:42123,op:havoc,rep:4
# id:000001,sig:11,src:000005,time:91234,op:splice,rep:8
```

Reproduce a crash:

```bash
# Local
./my_target/build/vuln workspace/crashes/default/crashes/id:000000,*

# With ASAN output
ASAN_OPTIONS=abort_on_error=1 ./vuln workspace/crashes/default/crashes/id:000000,*
```

### Coverage & stats

```bash
cat workspace/crashes/default/fuzzer_stats
afl-whatsup workspace/crashes/    # live dashboard
```

### LLM reasoning output

```bash
# Pre-phase context (seeds and mutators produced by the LLM)
ls workspace/corpus/
ls workspace/mutators/

# Attention distance matrix (human-readable)
cat workspace/distance_cache/attention_distances.json

# Persistent memory (reassessment history, coverage snapshots)
ls workspace/memory/

# Full orchestrator log
tail -f workspace/logs/orchestrator.log
```

### Resuming a run

The orchestrator persists pre-phase context to `workspace/memory/`. Re-running
with the same target config **skips the LLM pre-phase entirely** and reuses
cached seeds, mutators, and the attention matrix. This saves ~1–2 LLM calls on
every restart. To force regeneration, delete `workspace/memory/` or change the
target.

---

## 8. Troubleshooting

### `OPENAI_API_KEY not set` but I set a Gemini key

The provider is selected in the config, not the env. Edit `llm.provider` and
`llm.model` in the config file to match the key you set.

### `insufficient_quota` from OpenAI

ChatGPT Plus subscription does **not** include API credit. Fund the API
billing at https://platform.openai.com/settings/organization/billing (minimum
$5), or switch to Gemini's free tier.

### `afl-fuzz: command not found`

Use Docker mode (`./scripts/run.sh`) or install AFL++:
```bash
# Ubuntu/Debian
sudo apt install afl++
# Or build from source: https://github.com/AFLplusplus/AFLplusplus
```

### `No functions extracted from source`

The heuristic C/C++ parser in `AttentionComputer` expects standard function
definitions. Check:
- `source_dir` points to the actual source directory (not the build dir)
- Files have `.c`, `.cpp`, or `.cc` extensions
- Function definitions follow typical styles (K&R-style declarations may be missed)

### Fuzzer never hits a crash

Try:
- Increase `fuzzer.timeout` (try 3600s / 1 hour minimum)
- Lower `reassessment.plateau_threshold` (e.g. 120s) so the LLM rescues it sooner
- Verify the bug really is triggerable by running the target manually on a
  hand-crafted crash input first
- Check `workspace/logs/orchestrator.log` for LLM errors (malformed JSON, rate
  limits, etc.)

### Key accidentally committed

If you pushed a key to a public remote:
1. Revoke it immediately at the provider's console
2. Rotate to a new key
3. Use `git filter-repo` or GitHub's secret-scanning "push protection" to
   remove it from history
