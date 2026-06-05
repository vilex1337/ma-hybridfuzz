# Inference Server Setup

Two Kaggle notebooks serve different roles in the pipeline.

---

## Server 1 — Qwen2.5-Coder-14B (LLM)

Used for: seed generation, bug analysis, reassessment, function summarization.

1. Open https://www.kaggle.com/code/aneii11/dacn-inference
2. Kaggle Secrets required:
   - `NGROK_TOKEN` — from https://dashboard.ngrok.com/get-started/your-authtoken
   - `HF_TOKEN` — from https://huggingface.co/settings/tokens
3. Session option → Accelerator: **GPU T4 x2** (model needs ~28 GB VRAM)
4. Run all cells
5. Copy the `Public URL` from cell 6 → paste into `config.llm.base_url`

---

## Server 2 — LineVul Attention Distance (CodeBERT)

Used for: computing attention-based distances per basic block (pre-phase, Gap 1).

Notebook: `inference/linevul_attention_distance_server.ipynb`

1. Open [Google Colab](https://colab.research.google.com) and upload the notebook
2. Runtime → Change runtime type → **T4 GPU**
3. Colab Secrets required (left sidebar → key icon):
   - `NGROK_TOKEN` — from https://dashboard.ngrok.com/get-started/your-authtoken
4. Run all cells — the notebook downloads LineVul weights (~500 MB) from Google Drive automatically
5. Copy the `Public URL` from cell 7 → paste into config as `attention_distance.server_url`

> Note: No `HF_TOKEN` needed. `microsoft/codebert-base` is public. LineVul weights are
> fetched from the authors' Google Drive (`awsm-research/LineVul`) at startup.

**Endpoints exposed:**

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/score_blocks` | POST | Returns normalized attention scores `w(m) ∈ [0, 0.5]` per basic block |
| `/compute_distances` | POST | Returns `db_att = db_phys × (1.5 - w(m))` given blocks + physical distances |
| `/health` | GET | Model status and device info |
| `/metrics/<sid>` | GET | Cumulative blocks scored / requests for one fuzzer session |
| `/metrics` | GET | All fuzzer sessions plus aggregate totals |
| `/docs` | GET | Auto-generated FastAPI docs |

Both inference servers accept an optional `sid` field in request JSON. MA-HybridFuzz
generates a per-process session id automatically, or you can set `session.id` in
config / `MA_HYBRIDFUZZ_SID` to force a known id.

**Port:** 8001 (avoids conflict with Qwen server on 8000 if running both on same session)

---

## Running Both Servers Simultaneously

Host Server 1 on Kaggle, Server 2 on Google Colab
