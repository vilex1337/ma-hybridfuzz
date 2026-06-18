# Running the MA-HybridFuzz Benchmark on a VM

End-to-end guide for benchmarking the three fuzzers on Magma CVE targets,
24/7 on a VM, collecting the report metrics. Designed so you can **`git clone`
the repo and run the benchmark script** — no manual per-target steps.

## The three fuzzers

| `--fuzzer` | What it is | LLM | Tokens tracked |
|------------|-----------|-----|----------------|
| `deepseek` | MA-HybridFuzz + DeepSeek R1 | OpenAI-compatible client → `https://api.deepseek.com`, model `deepseek-reasoner` | yes (from API `usage`) |
| `chatgpt` (= `openai`) | MA-HybridFuzz + OpenAI model | direct OpenAI API, model `o4-mini` (set `OPENAI_MODEL`) | yes (from API `usage`) |
| `baseline` | Plain AFL++ (no LLM, no attention) | — | n/a (0) |

Both LLM fuzzers hit real APIs that return a `usage` field, so token/request
counts are exact (no proxy, no estimation). DeepSeek uses the generic
OpenAI-compatible client pointed at its endpoint — there is **no local proxy
server** to run.

Both LLM fuzzers run the **attention-distance model (LineVul/CodeBERT) locally on
CPU** — no Kaggle/Colab server. Weights (~500 MB) download once on first run into
`./models/` and are reused.

## Metrics collected (per run → `results/<fuzzer>/`)

Written to `workspace/bench/<fuzzer>/<CVE>/run_<i>/logs/overhead_metrics.csv`,
then aggregated:

- **Time-to-Reach (`ttr_s`)** and **Time-to-Exposure (`tte_s`)**
- **`llm_requests`**, **`llm_input_tokens`**, **`llm_output_tokens`**, plus derived
  **`input_tokens_per_hour`** / **`output_tokens_per_hour`** (= tokens ÷ fuzzing hours)
- `unique_crashes`, `edges_found`, `bitmap_cvg`, prep/overhead times

Baseline produces the same CSV schema (tokens/requests = 0) for like-for-like
comparison.

### Token accounting & parallel instances

Token/request counts are recorded **per process, locally** — each run counts the
`usage` field of its own API responses and writes its own CSV. Running several
instances on the **same** DeepSeek/cliproxy key is therefore safe: the counts do
not come from a shared server-side meter, so they never mix between instances.

Both OpenAI and DeepSeek return a `usage` field, so token totals are exact and
`llm_estimated_calls` should be `0`. The estimation fallback (count the request,
approximate tokens as chars/4, bump `llm_estimated_calls`) only triggers if an
API ever omits `usage` — a safety net rather than the expected path.

---

## 1. One-time setup

```bash
git clone <repo-url> ma-hybridfuzz && cd ma-hybridfuzz
./scripts/setup_vm.sh            # clones Magma into ./magma, builds images
cp .env.example .env             # if setup didn't already; then edit .env
```

`./magma` is **not** in the repo (it was a broken submodule); `setup_vm.sh`
clones HexHive/magma into it. Without it, Docker builds fail.

Fill in `.env`:
- `deepseek`: `DEEPSEEK_API_KEY=...`
- `chatgpt` / `openai`: `OPENAI_API_KEY=...` (optionally `OPENAI_MODEL=o4-mini`)
- `baseline`: nothing

## 2. LLM keys

Both LLM fuzzers call real APIs directly — no proxy server, no browser login.
Just put the keys in `.env`. The script preflight-checks that the relevant key
is set before launching. Set `OPENAI_MODEL` to the exact model id your key
supports (e.g. `o4-mini`, `o4`, `gpt-4o`). Output is **uncapped by default**
(`OPENAI_MAX_TOKENS=0` / `DEEPSEEK_MAX_TOKENS=0`) so reasoning tokens aren't
truncated and you can measure real consumption; set those to a number to cap
per-call output length. Token totals are recorded from each API response either
way — the cap only bounds output length, not measurement.

## 3. Run

```bash
# Baseline across every CVE config, 5 runs each, 3 in parallel (fits 4 cores/6GB)
./scripts/run_benchmark.sh --fuzzer baseline --cve all --runs 5 --parallel 3

# One CVE with DeepSeek
./scripts/run_benchmark.sh --fuzzer deepseek --cve CVE-2019-7317 --runs 5

# ChatGPT, all CVEs, 2 parallel
./scripts/run_benchmark.sh --fuzzer chatgpt --cve all --parallel 2

# See what would run without running it
./scripts/run_benchmark.sh --fuzzer baseline --cve all --list
```

Each run lasts `fuzzer.timeout` from the CVE config (21600 s = 6 h). The script
auto-discovers every `configs/magma/cve/**/CVE-*.yml`, so adding CVEs later needs
no script change.

Run the three fuzzers in sequence (or on separate VMs). Within one fuzzer the
script parallelizes `--parallel` jobs.

> **4 cores / 6 GB note.** Each fuzzing job is ~1 core in steady state, so CPU
> is not the limit — RAM is. Steady-state RSS per job:
> - **baseline**: ~0.3–0.6 GB → `--parallel 3` (even 4) is fine.
> - **deepseek / chatgpt**: LineVul loads ~1 GB only during pre-phase and is
>   **freed before the 6 h loop**, which then runs at ~0.4–0.6 GB. So
>   `--parallel 2` is comfortable (the brief overlap if two pre-phases coincide
>   is the only tight moment). `--parallel 3` is risky on 6 GB — avoid.
>
> Tuning knobs (env / .env): `LINEVUL_THREADS` (default 2) and `OMP_NUM_THREADS`
> (default 2) cap CPU threads so parallel pre-phases don't thrash; set
> `BENCH_MEM_LIMIT=2.5g` to hard-cap each LLM container's RAM as a safety net.
> For the cleanest `exec/s`/timing numbers use `--parallel 1`. The full 30×5
> matrix per fuzzer is ~900 run-hours (~19 days at parallel 2, ~13 at 3).

## 4. Resume after a crash / reboot

Resume is **on by default**. Re-run the *same command*:

```bash
./scripts/run_benchmark.sh --fuzzer baseline --cve all --runs 5 --parallel 3
```

Completed `(CVE, run)` jobs (CSV has a final `fuzzing_loop_time_s`) are skipped;
crashed/partial ones are re-run cleanly from scratch so every completed run is a
clean 6 h sample. `Ctrl-C` sends `TERM` to running containers so the orchestrator
flushes metrics before exiting. Use `--no-resume` to force everything to re-run.

## 5. Results

```
results/<fuzzer>/raw/<CVE>_<target>_<fuzzer>_run<id>.csv   # one durable file per run
results/<fuzzer>/<fuzzer>_runs.csv      # all runs in one table (+ totals & tokens/hour)
results/<fuzzer>/<fuzzer>_summary.csv   # per-CVE mean/median/stdev of key metrics
workspace/bench/<fuzzer>/<CVE>/run_<i>/ # raw AFL output + orchestrator.log
```

Each run writes its own file named **`cve_target_fuzzer_runid`** into
`results/<fuzzer>/raw/`. It is **rewritten every ~60 s while the run is live**, so
even if a run never finishes (reboot/OOM/Ctrl-C) you still have its latest
metrics — TTR/TTE/coverage/crashes/tokens so far. A `complete` column marks
whether the run reached its full budget; `fuzzing_loop_time_s` is filled only on
clean completion. Token columns include **`total_tokens`** and per-hour rates
(`input_/output_/total_tokens_per_hour`). `MA_SNAPSHOT_INTERVAL` (env) tunes the
flush cadence.

For your final report, average across a CVE's run files (the `_summary.csv`
already gives mean/median/stdev per metric). Re-aggregate anytime:

```bash
python3 scripts/aggregate_metrics.py results/baseline/raw --fuzzer baseline --out results/baseline
```

## 5b. Replicates & splitting across instances/VMs

Each replicate run is one process writing one uniquely-named file, so they never
collide. Two equivalent ways to get N replicates per CVE:

```bash
# One launch, 4 replicates, 2 running at a time:
./scripts/run_benchmark.sh --fuzzer chatgpt --cve all --runs 4 --parallel 2

# Split run-ids across two launches / two VMs (no collision):
#   machine A → ids 1,2 ;  machine B → ids 3,4
./scripts/run_benchmark.sh --fuzzer chatgpt --cve all --runs 2 --run-start 1
./scripts/run_benchmark.sh --fuzzer chatgpt --cve all --runs 2 --run-start 3
```

`--run-start` sets the first replicate id; `--runs` is how many ids this launch
covers. Fewer replicates (e.g. 4 instead of 5) is fine mechanically — just note
that fewer repeats widen the stddev / weaken statistical confidence.

## Notes / limitations

- **30-CVE selection** is still open: only 14 CVE configs exist
  (`configs/magma/cve/`). Add the rest as `configs/magma/cve/<lib>/<CVE>.yml`
  and they're picked up automatically.
- Baseline AFL++ is **undirected** (no attention, no AFLGo). The old directed
  AFLGo baseline is still available via `scripts/run_baseline.sh` if you want it.
- LineVul weights download from Google Drive on first LLM-fuzzer run; ensure the
  VM has outbound network the first time (cached in `./models/` afterwards).
