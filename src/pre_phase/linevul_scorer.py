"""
LineVul Scorer — computes attention-based block scores w(m) ∈ [0, 0.5].

Two modes (selected automatically):

  * **local** (default): loads the LineVul model (CodeBERT/RoBERTa) in-process and
    scores blocks on CPU. No external server required. This is the production
    path for the VM benchmark — see docs/BENCHMARK_VM.md.

  * **remote**: if ``server_url`` is set (and reachable), POSTs blocks to the
    Kaggle/Colab LineVul FastAPI server (legacy path).

If neither the local model nor the remote server can produce scores, the scorer
falls back to a uniform 0.5 for every block, which degrades the attention
distance to the plain *physical* distance (db_att = db_phys × 1.0).

The scoring math is ported verbatim from
``inference/linevul_attention_distance_server_v1_01.ipynb`` (cells 3–4):

  w_orig(m) = Σ_layers Σ_{content tokens} attn[CLS → token]      (formula 4)
  w(m)      = min-max normalise to [0, 0.5] with 90th-pct cap     (formulas 7–8)
"""
from __future__ import annotations

import logging
import os
from pathlib import Path

import requests

logger = logging.getLogger("pre_phase.linevul_scorer")

_TIMEOUT = 300  # seconds — remote scoring of many blocks can take a while

# ── LineVul model constants (mirror the notebook) ───────────────────────────
_BASE_MODEL = "microsoft/codebert-base"
_MAX_TOKENS = 512
_CAP_PERCENTILE = 90
# Fine-tuned LineVul head (awsm-research/LineVul) on the authors' Google Drive.
_WEIGHTS_GDRIVE_ID = "1oodyQqRb9jEcvLMVVKILmu8qHyNwd-zH"
_DEFAULT_WEIGHTS = "/models/12heads_linevul_model.bin"


class LineVulScorer:
    """Score basic blocks with LineVul attention; local CPU by default."""

    def __init__(self, server_url: str = "", sid: str = "default"):
        self._url = server_url.rstrip("/") if server_url else ""
        self._sid = sid or "default"
        # remote when an explicit URL is configured, else local in-process model
        self._mode = "remote" if self._url else "local"
        self._model = None
        self._tokenizer = None
        self._device = "cpu"
        self._local_failed = False

    # ── availability ────────────────────────────────────────────────────────

    def is_available(self) -> bool:
        if self._mode == "remote":
            try:
                r = requests.get(f"{self._url}/health", timeout=10)
                return r.status_code == 200
            except Exception:
                return False
        # local: available unless a prior load attempt failed
        if self._local_failed:
            return False
        return self._ensure_local_model()

    # ── public scoring API (unchanged signature) ─────────────────────────────

    def score_blocks(self, blocks: dict[str, str]) -> dict[str, float]:
        """Return normalised attention scores w(m) ∈ [0, 0.5] per block.

        Falls back to a uniform 0.5 for all blocks on any failure.
        """
        if not blocks:
            return {}
        if self._mode == "remote":
            return self._score_remote(blocks)
        return self._score_local(blocks)

    # ── remote (legacy server) ────────────────────────────────────────────────

    def _score_remote(self, blocks: dict[str, str]) -> dict[str, float]:
        try:
            resp = requests.post(
                f"{self._url}/score_blocks",
                json={"sid": self._sid, "blocks": blocks},
                timeout=_TIMEOUT,
            )
            resp.raise_for_status()
            return resp.json()["normalized_scores"]
        except Exception as e:
            logger.warning("LineVul server error (%s); using uniform scores", e)
            return {bb_id: 0.5 for bb_id in blocks}

    # ── local (in-process CPU model) ──────────────────────────────────────────

    def _ensure_local_model(self) -> bool:
        """Lazily load tokenizer + model. Returns True on success."""
        if self._model is not None:
            return True
        if self._local_failed:
            return False
        try:
            import argparse

            import torch
            import torch.nn as nn
            from transformers import (
                RobertaConfig,
                RobertaForSequenceClassification,
                RobertaTokenizer,
            )

            weights_path = os.getenv("LINEVUL_WEIGHTS", _DEFAULT_WEIGHTS)
            self._device = os.getenv("LINEVUL_DEVICE") or (
                "cuda" if torch.cuda.is_available() else "cpu"
            )

            self._ensure_weights(weights_path)

            # ── inline LineVul architecture (notebook cell 3) ─────────────────
            class _Head(nn.Module):
                def __init__(self, config):
                    super().__init__()
                    self.dense = nn.Linear(config.hidden_size, config.hidden_size)
                    self.dropout = nn.Dropout(config.hidden_dropout_prob)
                    self.out_proj = nn.Linear(config.hidden_size, 2)

                def forward(self, features, **kwargs):
                    x = features[:, 0, :]  # <s> / CLS token
                    x = self.dropout(x)
                    x = self.dense(x)
                    x = torch.tanh(x)
                    x = self.dropout(x)
                    return self.out_proj(x)

            class _Model(nn.Module):
                def __init__(self, encoder, config, tokenizer):
                    super().__init__()
                    self.encoder = encoder
                    self.tokenizer = tokenizer
                    self.classifier = _Head(config)

                def forward(self, input_ids=None, output_attentions=False):
                    outputs = self.encoder.roberta(
                        input_ids,
                        attention_mask=input_ids.ne(1),
                        output_attentions=output_attentions,
                    )
                    if output_attentions:
                        logits = self.classifier(outputs.last_hidden_state)
                        return torch.softmax(logits, dim=-1), outputs.attentions
                    logits = self.classifier(outputs[0])
                    return torch.softmax(logits, dim=-1)

            logger.info("[LineVul] Loading %s on %s ...", _BASE_MODEL, self._device)
            config = RobertaConfig.from_pretrained(_BASE_MODEL)
            config.num_labels = 1
            config.attn_implementation = "eager"
            self._tokenizer = RobertaTokenizer.from_pretrained(_BASE_MODEL)
            encoder = RobertaForSequenceClassification.from_pretrained(
                _BASE_MODEL,
                config=config,
                ignore_mismatched_sizes=True,
                attn_implementation="eager",
            )
            model = _Model(encoder, config, self._tokenizer)
            state = torch.load(weights_path, map_location=self._device)
            model.load_state_dict(state, strict=False)
            model.to(self._device)
            model.eval()
            self._model = model
            self._torch = torch
            # Cap CPU threads so parallel pre-phases don't oversubscribe the
            # cores (LINEVUL_THREADS=2 is a good default on a 4-core VM).
            n_threads = int(os.getenv("LINEVUL_THREADS", "0") or 0)
            if n_threads > 0:
                torch.set_num_threads(n_threads)
            logger.info("[LineVul] Local model ready (%s)", self._device)
            return True
        except Exception as exc:
            logger.warning(
                "[LineVul] Local model unavailable (%s); falling back to uniform "
                "scores (attention distance degrades to physical distance).",
                exc,
            )
            self._local_failed = True
            return False

    def _ensure_weights(self, weights_path: str) -> None:
        """Download the LineVul fine-tuned weights if they are not on disk."""
        path = Path(weights_path)
        if path.exists() and path.stat().st_size > 0:
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        logger.info("[LineVul] Downloading weights (~500MB) → %s", weights_path)
        try:
            import gdown

            gdown.download(
                f"https://drive.google.com/uc?id={_WEIGHTS_GDRIVE_ID}",
                str(path),
                quiet=False,
            )
        except Exception as exc:
            raise RuntimeError(f"LineVul weights download failed: {exc}") from exc
        if not path.exists() or path.stat().st_size == 0:
            raise RuntimeError(f"LineVul weights missing after download: {weights_path}")

    def release(self) -> None:
        """Drop the in-memory model/tokenizer to free ~1GB after pre-phase.

        Safe to call any time; scoring lazily reloads if ever needed again.
        The attention matrix is already cached to disk, so the 6h fuzzing loop
        never needs the model.
        """
        if self._model is None and self._tokenizer is None:
            return
        self._model = None
        self._tokenizer = None
        import gc

        gc.collect()
        logger.info("[LineVul] Released in-memory model (freed for the fuzzing loop)")

    def _score_local(self, blocks: dict[str, str]) -> dict[str, float]:
        if not self._ensure_local_model():
            return {bb_id: 0.5 for bb_id in blocks}
        try:
            raw = {
                bb_id: self._score_single_block(code)
                for bb_id, code in blocks.items()
            }
            return self._normalize(raw)
        except Exception as exc:
            logger.warning("[LineVul] Local scoring failed (%s); uniform scores", exc)
            return {bb_id: 0.5 for bb_id in blocks}

    def _score_single_block(self, code: str) -> float:
        """w_orig(m): sum of CLS→content-token attention over all layers."""
        torch = self._torch
        encoded = self._tokenizer(
            code,
            max_length=_MAX_TOKENS,
            truncation=True,
            padding="max_length",
            return_tensors="pt",
        )
        input_ids = encoded["input_ids"].to(self._device)
        with torch.no_grad():
            _prob, attentions = self._model(input_ids=input_ids, output_attentions=True)
        real_len = int(encoded["attention_mask"].sum().item())
        total = 0.0
        for layer_attn in attentions:
            mean_attn = layer_attn[0].mean(dim=0)         # avg over heads → [512,512]
            cls_row = mean_attn[0]                          # CLS attends to all tokens
            content = cls_row[1 : max(real_len - 1, 1)]    # skip CLS + final SEP
            total += float(content.sum().cpu())
        return total

    @staticmethod
    def _normalize(raw: dict[str, float]) -> dict[str, float]:
        """Min-max normalise raw scores to [0, 0.5] with a 90th-percentile cap."""
        if not raw:
            return {}
        import numpy as np

        values = np.array(list(raw.values()), dtype=float)
        w_max = float(np.percentile(values, _CAP_PERCENTILE))
        w_min = float(values.min())
        out: dict[str, float] = {}
        for bb_id, s in raw.items():
            if w_min == w_max:
                out[bb_id] = 0.5
            else:
                out[bb_id] = 0.5 * (min(s, w_max) - w_min) / (w_max - w_min)
        return out
