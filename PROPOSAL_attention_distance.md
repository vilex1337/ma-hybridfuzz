# Proposal: Attention Distance as Guidance Metric

**Date:** 2026-05-09  
**Context:** Replace the current LLM-prompt-based function-level distance approximation in `attention_computer.py` with a faithful implementation of the Attention Distance metric from Wang Bin et al. (2025).

---

## 1. Problem with Current Implementation

`src/pre_phase/attention_computer.py` asks a general LLM to rate "semantic relatedness" between pairs of **functions** (0.0–1.0). This is a coarse approximation that:

- Works at function level, missing intra-function control flow
- Uses a non-specialized general LLM (expensive, slow, imprecise)
- Ignores the physical distance component (CFG structure)
- Feeds only into the Python scheduler — AFL++ has no knowledge of it

The paper's Attention Distance works at **basic block level**, adjusting AFLGo physical distances with attention scores from a **fine-tuned vulnerability-aware CodeBERT model**. It yields 3.43× speedup over AFLGo and 2.89×/7.13× over DAFL/WindRanger.

---

## 2. Paper's Core Formula

```
db_att(m, Tb) = db_phys(m, Tb) × (Sa - w(m))
```

Where:
- `db_phys(m, Tb)` = AFLGo physical distance from basic block `m` to target block `Tb`
- `w(m)` = normalized attention score of block `m` (0.0–0.5, after capping top 10%)
- `Sa` = 1.5 (constant)

**Effect:** High attention score → multiply by smaller factor → shorter attention distance → higher seed priority. Low attention → longer distance → deprioritized.

**Physical distance (function-level, formula 5):**
```
d_f(n, Tf) = harmonic_mean(d_callgraph(n, tf) for tf in reachable_targets)
```

**Physical distance (block-level, formula 6):**
```
db_phys(m, Tb) = c × min_{n in N(m)}(d_f(n, Tf))   if m in T
              = [sum_{t in T}(db(m,t) + db(t, Tb))]^-1  otherwise
```

**Attention score aggregation (formula 4):**
```
LineScore(line) = sum_{layers} sum_{tokens in line} s_ij
w_orig(m) = sum of LineScores for all lines in block m
```

**Normalization (formulas 7–8):**
```
w_max = 90th percentile of all w_orig values  (cap to reduce outliers)
w(m) = 0.5                                    if w_min == w_max
     = (min(w_orig(m), w_max) - w_min) / (w_max - w_min)  otherwise
```

---

## 3. Architecture

### 3.1 Component Overview

```
Source Code
    │
    ▼
[CFGExtractor]          ← new: src/pre_phase/cfg_extractor.py
    │  LLVM IR parsing
    │  Output: {bb_id → source_lines, call_graph, bb_to_func}
    │
    ▼
[LineVulScorer]         ← new: src/pre_phase/linevul_scorer.py
    │  Fine-tuned CodeBERT (LineVul checkpoint)
    │  Input: source lines per basic block
    │  Output: {bb_id → normalized_attention_score w(m)}
    │
    ▼
[AttentionDistanceComputer]   ← replaces: src/pre_phase/attention_computer.py
    │  Combines physical distance (formulas 5,6) + attention score (formula 9)
    │  Output A: distance.cfg.txt  (AFLGo-compatible, for AFL++ instrumentation)
    │  Output B: attention_distances.pkl/json  (for Python scheduler)
    │
    ├──▶ [AFLRunner]     ← modified: src/fuzzing/afl_runner.py
    │        Pass distance.cfg.txt via AFL_LLVM_AFLGO_INST_RATIO + afl-clang-fast
    │
    └──▶ [AttentionScheduler]  ← modified: src/fuzzing/scheduler.py
             Block-level priority: min attention distance over reached blocks
```

### 3.2 Data Flow

**Pre-phase (once per target):**
1. Compile target with `clang -S -emit-llvm` → `target.ll`
2. Parse LLVM IR → extract basic blocks, call graph, BB→source line mappings
3. Run LineVul on each BB's source lines → raw attention scores
4. Normalize scores → `w(m)` per BB
5. Compute physical distances (formulas 5, 6) from call graph + CFG
6. Compute attention distances (formula 9) per BB
7. Write `distance.cfg.txt` (format: `func_name,bb_id:distance` per line)
8. Cache as `attention_distances.pkl` (for scheduler)

**Fuzzing loop (per seed, in scheduler):**
- Look up reached basic blocks (from coverage data)
- Find minimum attention distance to target block
- Feed into existing priority formula

---

## 4. Technology Choices

| Component | Technology | Rationale |
|-----------|-----------|-----------|
| LLVM IR extraction | `clang -S -emit-llvm` + regex/text parse of `.ll` file | No extra deps; LLVM already required for AFL++; avoids llvmlite complexity |
| Physical distance computation | Python (formulas 5, 6 directly) | ~80 lines; no library needed |
| Attention model | `transformers` + LineVul checkpoint (`MichaelFu512/LineVul` on HuggingFace) | Paper's exact model; 500MB; runs on CPU; no GPU required |
| Inference | HuggingFace `pipeline` or direct `AutoModel` | Standard, well-maintained |
| Distance file format | AFLGo `distance.cfg.txt` text format | Compatible with AFL++ AFLGo mode; enables native seed scheduling in AFL++ |
| Caching | Pickle + JSON (existing pattern) | Consistent with current code; avoids re-running model |

**LineVul checkpoint:** `MichaelFu512/LineVul` — CodeBERT fine-tuned on 188,636 C/C++ vulnerability functions (same dataset cited in paper). Produces per-token attention weights across 12 Transformer layers.

**Alternative if LineVul unavailable:** Fall back to existing LLM-prompt scoring (keep current `AttentionComputer` as fallback). This is a graceful degradation path, not the primary implementation.

---

## 5. Files to Create / Modify

### New Files

**`src/pre_phase/cfg_extractor.py`**
```
Class: CFGExtractor
- compile_to_llvm_ir(source_dir, binary_name) → llvm_ir_path
- extract_basic_blocks(llvm_ir_path) → {bb_id: {lines, func, successors}}
- extract_call_graph(llvm_ir_path) → {func: [called_funcs]}
- map_bb_to_source_lines(bb_data, source_dir) → {bb_id: [source_line_strs]}
```

**`src/pre_phase/linevul_scorer.py`**
```
Class: LineVulScorer
- __init__(model_name="MichaelFu512/LineVul")
- score_basic_blocks(bb_source_map: dict) → {bb_id: float}
  - tokenize lines in BB
  - run forward pass, extract attention from all 12 layers
  - aggregate: LineScore = sum over layers and tokens (formula 4)
  - aggregate per BB: sum of its line scores
  - normalize across all BBs: cap top 10%, min-max scale to [0, 0.5] (formula 7,8)
```

**`src/pre_phase/attention_distance_computer.py`** (replaces `attention_computer.py`)
```
Class: AttentionDistanceComputer
- compute(source_dir, target_function, target_bb=None)
  1. CFGExtractor → IR, BBs, call graph
  2. LineVulScorer → {bb_id: w(m)}
  3. _compute_physical_distances(call_graph, cfg, target_function) → {bb_id: float}
  4. _compute_attention_distances(phys, attention) → {bb_id: float}
  5. write_distance_cfg_txt(distances) → path
  6. write_cache(distances, bb_data, w_scores)
- load_cached() → dict
- get_distance(bb_id) → float
- get_neighbors(target_function, top_k=3) → [func_names]  ← preserve existing interface
```

### Modified Files

**`src/fuzzing/afl_runner.py`**
- Add: if `distance.cfg.txt` exists, set `AFL_LLVM_INSTRUMENT=CLASSIC` and pass distance file path during binary instrumentation (AFLGo mode in AFL++)
- Existing logic unchanged if distance file absent

**`src/fuzzing/scheduler.py`**
- Update `_compute_attention_score` to accept basic block IDs in addition to function names
- Update `set_distance_matrix` to load block-level distances from new cache format
- Preserve existing function-level fallback

**`src/orchestrator.py`**
- Replace `AttentionComputer` import with `AttentionDistanceComputer`
- Pass `distance.cfg.txt` path to `AFLRunner` after pre-phase

**`requirements.txt`**
- Add: `transformers>=4.40.0`, `torch>=2.0.0` (CPU build sufficient)

---

## 6. AFL++ Distance File Integration

The paper builds on AFLGo, which instruments binaries at compile time with distance information. AFL++ supports this via:

```bash
# During instrumentation:
AFL_LLVM_INSTRUMENT=CLASSIC \
AFL_CUSTOM_INFO_OUT=./distance.cfg.txt \
afl-clang-fast -o target_afl target.c
```

The `distance.cfg.txt` format (AFLGo-compatible):
```
main,1:4.500000
main,2:3.200000
parse_header,5:1.100000
parse_header,6:0.300000
...
```

If AFL++ AFLGo mode is not available (depends on build), the distance file still feeds the Python scheduler as a fallback — no change to fuzzing correctness, only to scheduling granularity.

---

## 7. Key Constraints and Tradeoffs

| Decision | Choice | Tradeoff |
|----------|--------|----------|
| Granularity | Basic block (paper's level) | More precise than function-level; requires LLVM IR parse |
| Model | LineVul (fine-tuned) | Faithful to paper; one-time ~500MB download; no per-query LLM cost |
| LLVM IR parsing | Text parse of `.ll` | Simpler than llvmlite; fragile on complex IR but sufficient for function/BB extraction |
| Fallback | Keep old `AttentionComputer` as fallback | Graceful degradation; no breaking changes |
| AFL++ mode | AFLGo-compatible if available | Enables native distance-based scheduling in AFL++ at zero scheduler overhead |

**Assumption to confirm:** The target binary's source is compilable with `clang` (needed for LLVM IR). If not (e.g., binary-only targets), fall back to function-level scoring.

---

## 8. Implementation Steps (for agent)

```
1. Create cfg_extractor.py
   → verify: parse jsoncpp's LLVM IR, extract ≥10 BBs with source lines

2. Create linevul_scorer.py
   → verify: score 5 sample BBs from jsoncpp, values in [0, 0.5]

3. Create attention_distance_computer.py
   → verify: produces distance.cfg.txt with one entry per BB
   → verify: load_cached() returns same data
   → verify: get_neighbors() returns top-3 functions (backward compat)

4. Modify orchestrator.py
   → verify: pre-phase completes without error on jsoncpp config

5. Modify afl_runner.py
   → verify: afl-clang-fast build includes distance file env var when file exists

6. Modify scheduler.py
   → verify: compute_priority() uses block distances when available

7. Integration test: run full pipeline on jsoncpp
   → verify: fuzzer_stats shows execs_per_sec > 0 after 60s
```

---

## 9. What Does NOT Change

- Seed generation pipeline (reasoning_agent, seed_generator)
- Mutator generation (mutator_generator)
- Reassessment logic (reassessment_agent)
- LLM provider abstraction
- Coverage checker
- All config keys (scheduler weights, paths, etc.)

The change is surgical: replace the distance computation engine while preserving all other interfaces.
