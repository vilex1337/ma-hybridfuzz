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

# Optional: include important internal service/computation logs
./scripts/run.sh configs/default.yml --verbosity 2
```

For the full walkthrough (including OpenAI/Anthropic, Docker, troubleshooting,
inspecting crashes), see **[docs/SETUP.md](docs/SETUP.md)**.

## Benchmark Suite (VM — 3 fuzzers × Magma CVEs)

For the experiments we run on a VM, use **`scripts/run_benchmark.sh`**. It runs one
fuzzer over selected Magma CVE targets, N replicate runs each (~6 h per run),
with bounded parallelism, automatic resume, and per-run metrics. Full guide:
**[docs/BENCHMARK_VM.md](docs/BENCHMARK_VM.md)**.

### The three fuzzers

| `--fuzzer` | What it is | Needs |
|------------|-----------|-------|
| `deepseek` | MA-HybridFuzz + DeepSeek R1 (OpenAI-compatible API) | `DEEPSEEK_API_KEY` |
| `chatgpt` (= `openai`) | MA-HybridFuzz + an OpenAI model (default `o4-mini`) | `OPENAI_API_KEY` |
| `baseline` | Plain AFL++ (no LLM, no attention) | nothing |

Both LLM fuzzers compute attention distance with a **local CPU LineVul model**
(no external server). The baseline seeds from the Magma corpus.

### Setup (one target at a time)

On a resource-limited VM you don't build all libraries up front. `setup_vm.sh`
takes a **single target** and builds only that library's image, so you can:
**set up one target → benchmark all its CVEs → release it → move to the next.**

```bash
git clone <repo-url> ma-hybridfuzz && cd ma-hybridfuzz
nano .env                      # set DEEPSEEK_API_KEY and/or OPENAI_API_KEY (see .env.example)

./scripts/setup_vm.sh --list   # show targets: libpng libtiff libxml2 openssl sqlite3 poppler php
./scripts/setup_vm.sh libpng   # clones Magma into ./magma, checks Docker, builds ONLY magma-libpng
```

`setup_vm.sh all` builds every library (the old behaviour). The first run always
clones `./magma`, which is **not** in the repo — without it the Docker builds fail.

When you finish a target, free its image before setting up the next one
(`setup_vm.sh` prints the exact command on completion):

```bash
docker rmi $(docker images -q 'ma-hybridfuzz*magma-libpng*') 2>/dev/null; docker image prune -f
```

### Smoke test before the 6-hour runs

Run each fuzzer once with a short timeout and check the output file:

```bash
./scripts/run_benchmark.sh --fuzzer baseline --cve CVE-2019-7317 --runs 1 --timeout 600
./scripts/run_benchmark.sh --fuzzer chatgpt  --cve CVE-2019-7317 --runs 1 --timeout 600
./scripts/run_benchmark.sh --fuzzer deepseek --cve CVE-2019-7317 --runs 1 --timeout 600
cat results/chatgpt/raw/CVE-2019-7317_png_image_free_chatgpt_run1.csv
```

Expect `complete=True`, `fuzzing_loop_time_s≈600`, `total_tokens>0`, and
`llm_estimated_calls=0` (real token usage is flowing). Run the LLM smoke tests
**one at a time first** so the LineVul weights download into `./models/` once.

### Per-target runs (resource-limited workflow)

Benchmark **all CVEs of one target** with `--target`, and cap how many CVEs to
run with `--max-cves` when time is tight. Use tmux/nohup so runs survive a
disconnect.

```bash
# 2 CVEs of libpng × 2 runs each, 2 in parallel (~6 h per run = two ~6 h waves):
./scripts/run_benchmark.sh --fuzzer baseline --target libpng --max-cves 2 --runs 2 --parallel 2

# then free the image and move to the next target
docker rmi $(docker images -q 'ma-hybridfuzz*magma-libpng*') 2>/dev/null; docker image prune -f
./scripts/setup_vm.sh libtiff
./scripts/run_benchmark.sh --fuzzer baseline --target libtiff --max-cves 2 --runs 2 --parallel 2
```

`--target <lib>` selects every CVE under `configs/magma/cve/<lib>/`; `--max-cves N`
keeps the first N (alphabetical) and logs the ones it drops. Each run is hard-capped
at `--timeout` + a grace period (`MA_TIMEOUT_GRACE`, default 900 s) so a run can
never overrun 6 h even if a reassessment LLM call is in flight at the deadline.

### Full runs (all CVEs of all targets)

```bash
./scripts/run_benchmark.sh --fuzzer baseline --cve all --runs 5 --parallel 3
./scripts/run_benchmark.sh --fuzzer deepseek --cve all --runs 5 --parallel 2
./scripts/run_benchmark.sh --fuzzer chatgpt  --cve all --runs 5 --parallel 2
```

`--parallel`: baseline 3 fits a 4-core/6 GB VM; the LLM fuzzers are heavier
(LineVul), so use 2.

### Common options

| Flag | Meaning |
|------|---------|
| `--fuzzer <name>` | `deepseek` \| `chatgpt`/`openai` \| `baseline` (required) |
| `--target <lib>` | restrict to all CVEs of one library (`libpng`, `libtiff`, …) |
| `--cve <ID\|all>` | one CVE (e.g. `CVE-2019-7317`) or every config in scope (default `all`) |
| `--max-cves N` | cap to the first N CVEs of the selection (`0` = no cap) |
| `--runs N` | replicate runs per CVE (default 5) |
| `--run-start S` | first replicate id (default 1) — shard ids across VMs |
| `--parallel N` | concurrent runs (default 3) |
| `--timeout S` | seconds per run (default 21600 = 6 h); lower it for smoke tests |
| `--build` | rebuild images before running |
| `--no-resume` | re-run everything instead of skipping completed runs |
| `--list` | print the targets a run would cover, then exit |

### Resume & sharding

Resume is **on by default** — just re-run the same command after a crash/reboot;
completed runs are skipped, partial ones re-run cleanly. To split replicate ids
across two machines:

```bash
# VM-A: ids 1-3            # VM-B: ids 4-5
./scripts/run_benchmark.sh --fuzzer deepseek --cve all --runs 3 --run-start 1
./scripts/run_benchmark.sh --fuzzer deepseek --cve all --runs 2 --run-start 4
```

### Where the metrics go

```
results/<fuzzer>/raw/<CVE>_<target>_<fuzzer>_run<id>.csv   # one durable file per run
results/<fuzzer>/<fuzzer>_runs.csv                          # all runs in one table
results/<fuzzer>/<fuzzer>_summary.csv                       # per-CVE mean/median/stdev
```

Per-run files are **rewritten every ~60 s while a run is live**, so metrics
survive an interrupted run (a `complete` column marks full runs). They include
TTR (`ttr_s`), TTE (`tte_s`), crashes, coverage, LLM requests, `total_tokens`,
and per-hour token rates. Re-aggregate anytime:

```bash
python3 scripts/aggregate_metrics.py results/deepseek/raw --fuzzer deepseek --out results/deepseek
```

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

logging:
  verbosity: 1   # 0=warnings, 1=high-level, 2=important internals, 3=debug
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
