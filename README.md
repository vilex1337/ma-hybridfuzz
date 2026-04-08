# MA-HybridFuzz

**Multi-Agent Hybrid Directed Fuzzing with On-Demand LLM Guidance for Efficient PoV Generation**

A directed fuzzing framework that combines LLM-generated seeds/mutators (Gap 3) with attention-based semantic distance guidance (Gap 1) for efficient vulnerability discovery.

## Architecture

```
Pre-phase (LLM)          Fuzzing Loop (Native)        Reassessment (On-demand)
+-----------------+      +--------------------+       +-------------------+
| Reasoning Agent |----->| AFL++ Engine       |------>| Plateau Detection |
| Seed Generator  |      | Attention Scheduler|       | LLM Re-analysis   |
| Mutator Gen     |      | Custom Mutators    |       | New Seeds/Mutators|
| Attention Calc  |      | Crash Oracle       |       +-------------------+
+-----------------+      +--------------------+
```

## Quick Start

```bash
# 1. Clone and setup
git clone <repo-url> && cd ma-hybridfuzz
cp .env.example .env
# Edit .env with your ANTHROPIC_API_KEY

# 2. Setup
./scripts/setup.sh

# 3. Configure target in configs/default.yml

# 4. Run
./scripts/run.sh
```

## Configuration

Edit `configs/default.yml`:

```yaml
target:
  binary: "/path/to/target"
  source_dir: "/path/to/source"
  target_function: "vulnerable_func"
  bug_type: "buffer_overflow"
```

## Project Structure

```
.
├── configs/             # Configuration files
│   └── default.yml
├── docker/              # Docker build files
│   └── Dockerfile.fuzzer
├── docs/                # Documentation
│   └── ARCHITECTURE.md
├── scripts/             # Setup and run scripts
│   ├── setup.sh
│   └── run.sh
├── src/                 # Source code
│   ├── orchestrator.py  # Main pipeline coordinator
│   ├── pre_phase/       # Gap 3: LLM pre-generation
│   │   ├── reasoning_agent.py
│   │   ├── seed_generator.py
│   │   ├── mutator_generator.py
│   │   └── attention_computer.py
│   └── fuzzing/         # Gap 1: Attention-guided fuzzing
│       ├── afl_runner.py
│       └── scheduler.py
├── workspace/           # Runtime data (gitignored)
├── docker-compose.yml
└── requirements.txt
```

## Research Gaps Addressed

| Gap | Description | Implementation |
|-----|-------------|----------------|
| Gap 1 | Attention Distance as semantic metric | `src/pre_phase/attention_computer.py`, `src/fuzzing/scheduler.py` |
| Gap 3 | LLM pre-generated seeds & mutators | `src/pre_phase/seed_generator.py`, `src/pre_phase/mutator_generator.py` |

## Requirements

- Docker & Docker Compose
- Anthropic API key (Claude)
