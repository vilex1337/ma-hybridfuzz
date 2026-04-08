"""
Seed Generator - Uses LLM to generate reachable seeds based on
Function Call Chain (FCC) analysis. (Gap 3 - RANDLUZZ-inspired)
"""

import json
import logging
import os
from base64 import b64decode, b64encode
from pathlib import Path

import anthropic

logger = logging.getLogger("pre_phase.seed_gen")


class SeedGenerator:
    def __init__(self, config: dict):
        self.config = config
        self.client = anthropic.Anthropic()
        self.model = config["llm"]["model"]
        self.corpus_dir = Path(config["paths"]["corpus"])
        self.corpus_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, analysis: dict, count: int = 20) -> list[Path]:
        """Generate reachable seeds based on target analysis."""
        paths = analysis.get("paths", [])
        constraints = analysis.get("constraints", [])
        input_format = analysis.get("input_format", "binary")

        prompt = f"""You are generating seed inputs for a directed fuzzer targeting a C/C++ program.

Target analysis:
- Function call paths: {json.dumps(paths[:5])}
- Input constraints: {json.dumps(constraints[:10])}
- Input format: {input_format}

Generate {count} seed inputs that are likely to reach the target function.
Each seed should satisfy as many constraints as possible.

For each seed, provide:
- "name": descriptive filename
- "content_b64": base64-encoded content of the seed
- "rationale": why this seed should reach the target

Return a JSON object with key "seeds" containing the list.
Return ONLY valid JSON."""

        response = self.client.messages.create(
            model=self.model,
            max_tokens=self.config["llm"]["max_tokens"],
            temperature=self.config["llm"]["temperature"],
            messages=[{"role": "user", "content": prompt}],
        )

        seeds = self._parse_seeds(response.content[0].text)
        saved = self._save_seeds(seeds)
        return saved

    def _parse_seeds(self, text: str) -> list[dict]:
        try:
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0]
            elif "```" in text:
                text = text.split("```")[1].split("```")[0]
            data = json.loads(text.strip())
            return data.get("seeds", [])
        except (json.JSONDecodeError, IndexError) as e:
            logger.error("Failed to parse seed response: %s", e)
            return []

    def _save_seeds(self, seeds: list[dict]) -> list[Path]:
        saved = []
        for i, seed in enumerate(seeds):
            name = seed.get("name", f"seed_{i:03d}")
            # Sanitize filename
            name = "".join(c for c in name if c.isalnum() or c in "._-")
            fpath = self.corpus_dir / name

            try:
                content_b64 = seed.get("content_b64", "")
                content = b64decode(content_b64)
            except Exception:
                # Fall back to raw content if base64 fails
                raw = seed.get("content", seed.get("content_b64", ""))
                content = raw.encode() if isinstance(raw, str) else b""

            if content:
                fpath.write_bytes(content)
                saved.append(fpath)
                logger.info("Saved seed: %s (%d bytes)", name, len(content))

        return saved
