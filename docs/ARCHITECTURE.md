# MA-HybridFuzz Architecture

## Overview

MA-HybridFuzz is a multi-agent hybrid directed fuzzing framework that addresses:
- **Gap 3**: LLM pre-generated reachable seeds & bug-specific mutators (RANDLUZZ-inspired)
- **Gap 1**: Attention distance as semantic guidance metric (Attention Distance-inspired)

The system uses strict on-demand LLM calls only in pre-phase and when stuck,
keeping the main fuzzing loop running at native speed.

---

## Architecture Diagram

```
+============================================================================+
|                           MA-HybridFuzz System                             |
+============================================================================+
|                                                                            |
|  +---------------------------+     +-----------------------------------+   |
|  |     INPUT SOURCES         |     |     ORCHESTRATOR (Main Agent)     |   |
|  |                           |     |                                   |   |
|  |  - Target binary/source   |---->|  - Pipeline coordinator           |   |
|  |  - Bug info (CVE, crash)  |     |  - Phase transition logic        |   |
|  |  - Target function(s)     |     |  - Stuck detection & LLM recall  |   |
|  +---------------------------+     +--------+---------+----------------+   |
|                                             |         |                    |
|                    +------------------------+         |                    |
|                    v                                  v                    |
|  +=================+===============+  +===============+================+   |
|  |        PHASE 1: PRE-PHASE      |  |    PHASE 2: FUZZING LOOP       |   |
|  |         (Gap 3 - LLM)          |  |    (Gap 1 - Native Speed)      |   |
|  +=================================+  +================================+   |
|  |                                 |  |                                |   |
|  | +-----------------------------+ |  | +----------------------------+ |   |
|  | | Reasoning Agent             | |  | | AFL++ Engine               | |   |
|  | |                             | |  | |                            | |   |
|  | | - Analyze target source     | |  | | - Instrumented PUT         | |   |
|  | | - Identify paths to target  | |  | | - Fork server              | |   |
|  | | - Extract constraints       | |  | | - Coverage bitmap          | |   |
|  | +-----------------------------+ |  | +----------------------------+ |   |
|  |              |                  |  |              |                |   |
|  |              v                  |  |              v                |   |
|  | +-----------------------------+ |  | +----------------------------+ |   |
|  | | Seed Generator Agent        | |  | | Attention Distance Calc    | |   |
|  | |                             | |  | | (Pre-computed)             | |   |
|  | | - Generate reachable seeds  | |  | |                            | |   |
|  | |   via FCC analysis          | |  | | - LLM attention scores     | |   |
|  | | - Seeds target specific     | |  | |   (cached from pre-phase)  | |   |
|  | |   code paths                | |  | | - Semantic distance matrix | |   |
|  | +-----------------------------+ |  | | - Function-level weights   | |   |
|  |              |                  |  | +----------------------------+ |   |
|  |              v                  |  |              |                |   |
|  | +-----------------------------+ |  |              v                |   |
|  | | Mutator Generator Agent     | |  | +----------------------------+ |   |
|  | |                             | |  | | Seed Scheduler             | |   |
|  | | - Bug-specific mutators     | |  | |                            | |   |
|  | | - Constraint-aware          | |  | | - Priority = f(attention   | |   |
|  | |   mutation strategies       | |  | |   distance, coverage,      | |   |
|  | | - Custom grammar rules      | |  | |   exec speed)              | |   |
|  | +-----------------------------+ |  | | - Energy assignment         | |   |
|  |              |                  |  | +----------------------------+ |   |
|  |              v                  |  |              |                |   |
|  | +-----------------------------+ |  |              v                |   |
|  | | Attention Score Computer    | |  | +----------------------------+ |   |
|  | |                             | |  | | Custom Mutator Engine      | |   |
|  | | - Feed source to LLM        | |  | |                            | |   |
|  | | - Extract attention weights | |  | | - Apply pre-gen mutators   | |   |
|  | | - Build distance matrix     | |  | | - Standard AFL++ mutators  | |   |
|  | | - Cache for fuzzing loop    | |  | | - Havoc + bug-specific     | |   |
|  | +-----------------------------+ |  | +----------------------------+ |   |
|  |                                 |  |              |                |   |
|  +=================================+  |              v                |   |
|                    |                  | +----------------------------+ |   |
|                    |                  | | Oracle (Crash Detector)    | |   |
|                    |  Seeds,          | |                            | |   |
|                    |  Mutators,       | | - ASAN/UBSAN signals       | |   |
|                    |  Distance Matrix | | - Crash dedup              | |   |
|                    |                  | | - PoV candidate tagging    | |   |
|                    +----------------->| +----------------------------+ |   |
|                                       |                                |   |
|                                       +================================+   |
|                                                      |                     |
|                              +=======================+=================+   |
|                              |   PHASE 3: ON-DEMAND REASSESSMENT      |   |
|                              |   (Triggered when stuck)               |   |
|                              +=========================================+   |
|                              |                                         |   |
|                              | - Detect plateau (no new coverage       |   |
|                              |   for N minutes)                        |   |
|                              | - LLM re-analyzes current state         |   |
|                              | - Generate new seeds/mutators           |   |
|                              | - Update attention distance matrix      |   |
|                              | - Feed back into fuzzing loop           |   |
|                              |                                         |   |
|                              +=========================================+   |
|                                                                            |
|  +=====================================================================+  |
|  |                     PERSISTENT STORAGE                               |  |
|  +=====================================================================+  |
|  |                                                                      |  |
|  |  /corpus/          - Seed corpus (pre-gen + discovered)              |  |
|  |  /crashes/         - Crash inputs + PoV candidates                   |  |
|  |  /mutators/        - Custom mutator definitions                      |  |
|  |  /distance_cache/  - Attention distance matrix (pre-computed)        |  |
|  |  /coverage/        - Coverage bitmaps & stats                        |  |
|  |  /logs/            - Fuzzing stats, agent decisions                  |  |
|  |                                                                      |  |
|  +=====================================================================+  |
|                                                                            |
+============================================================================+
```

## Component Details

### 1. Orchestrator (Main Agent)
- Coordinates the entire pipeline
- Manages phase transitions: Pre-phase -> Fuzzing -> Reassessment
- Detects when fuzzer is "stuck" (coverage plateau) and triggers LLM reassessment
- Collects and reports results

### 2. Pre-Phase (Gap 3 Implementation)
**Reasoning Agent**: Analyzes target source code, bug descriptions, and identifies
feasible paths to the target location.

**Seed Generator**: Uses LLM with Function Call Chain (FCC) analysis to generate
seeds that can reach the target function. Unlike random seeds, these are
semantically meaningful inputs.

**Mutator Generator**: Creates bug-specific mutation strategies based on the
vulnerability type (buffer overflow, use-after-free, integer overflow, etc.).

**Attention Score Computer**: Feeds source code through LLM, extracts attention
weights between functions, and builds a semantic distance matrix that replaces
traditional physical/static distance.

### 3. Fuzzing Loop (Gap 1 Implementation)
**AFL++ Engine**: Industry-standard fuzzer as the base. Handles instrumentation,
fork server, and execution.

**Attention Distance Calculator**: Uses the pre-computed attention distance matrix
to calculate semantic distance from any basic block to the target. This replaces
AFL++'s default distance calculation.

**Seed Scheduler**: Prioritizes seeds based on attention distance (lower = closer
to target semantically), coverage novelty, and execution speed.

**Custom Mutator Engine**: Applies the pre-generated bug-specific mutators
alongside standard AFL++ havoc mutations.

**Oracle**: Detects crashes via ASAN/UBSAN, deduplicates, and tags PoV candidates.

### 4. On-Demand Reassessment
Triggered only when the fuzzer hits a coverage plateau. The LLM is called to:
- Analyze current coverage state
- Generate new targeted seeds
- Adjust mutation strategies
- Update distance matrix if needed

## Data Flow

```
1. User provides: target binary + source + bug info
2. Pre-phase (LLM): generates seeds, mutators, attention distance matrix
3. Fuzzing loop (native): AFL++ with attention-guided scheduling
4. If stuck: LLM reassessment -> new seeds/mutators -> back to step 3
5. Output: crashes, PoV candidates, coverage stats
```

## Docker Architecture

```
docker-compose.yml
  |
  +-- fuzzer-core        (AFL++ with custom mutators & distance metric)
  +-- pre-phase          (LLM agents for seed/mutator generation)
  +-- orchestrator       (Pipeline coordination)
```

All components communicate via shared volumes and a simple message queue.
