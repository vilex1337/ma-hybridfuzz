"""
Seed Generator - Materialises RANDLUZZ-style seed dicts (produced by ReasoningAgent)
to disk as concrete files in the AFL++ corpus directory.

Seed dicts come from three RANDLUZZ generation paths (§3.3):
  - Preliminary seed generation (§3.3.1)
  - Reasoning along FCC          (§3.3.2)
  - Reasoning based on Functionality (§3.3.3)

Each dict carries either a raw string (seed_type="string") or a Python script
(seed_type="code") that is executed to produce binary files.
"""

import logging
from pathlib import Path

from config import AppConfig

logger = logging.getLogger("pre_phase.seed_gen")


class SeedGenerator:
    def __init__(self, config: AppConfig):
        self.config = config
        self.corpus_dir = Path(config.paths.corpus).resolve()
        self.corpus_dir.mkdir(parents=True, exist_ok=True)
        self._code_retries = config.seed_generator.code_retries
        self._provider = None
        self._max_tokens = config.llm.max_tokens

    def _get_provider(self):
        """Lazy-init the LLM provider (only needed for code-fix retries)."""
        if self._provider is None:
            from llm.provider import create_provider
            self._provider = create_provider(self.config)
        return self._provider

    def write_seeds(self, seed_dicts: list[dict]) -> list[Path]:
        """
        Materialise RANDLUZZ-style seed dicts produced by ReasoningAgent to disk.

        Each dict may contain:
          seed_type    : "string" or "code"
          seed_content : raw string content (used when seed_type == "string")
          seed_code    : Python script that writes the seed file (seed_type == "code")
          seed_description / rationale : used for naming

        For seed_type == "code", the Python script is executed and its output file
        is moved into the corpus directory.  If execution fails the error is logged
        and that seed is skipped.
        """
        saved = []
        for i, seed in enumerate(seed_dicts):
            seed_type = seed.get("seed_type", "string")
            description = seed.get(
                "seed_description",
                seed.get("rationale", seed.get("modification_rationale", f"seed_{i:03d}")),
            )
            # Build a safe filename from the description
            base_name = "".join(
                c if (c.isalnum() or c in "._-") else "_"
                for c in description[:40]
            ).strip("_") or f"seed_{i:03d}"

            if seed_type == "string":
                content_str = seed.get("seed_content", "")
                if not content_str:
                    continue
                fpath = self._unique_path(base_name)
                fpath.write_bytes(content_str.encode())
                saved.append(fpath)
                logger.info("Wrote string seed: %s (%d bytes)", fpath.name, len(content_str))

            elif seed_type == "code":
                code = seed.get("seed_code", "")
                if not code:
                    continue
                out_path = self._unique_path(base_name)
                result = self._run_seed_code_with_retry(code, out_path)
                if result:
                    saved.append(result)
                else:
                    # Safety fallback: all retries exhausted — write a minimal placeholder
                    # so AFL++ never starts with an empty corpus.
                    out_path.write_bytes(b"\x00")
                    saved.append(out_path)
                    logger.warning(
                        "Seed code failed all %d attempt(s) — wrote 1-byte fallback seed: %s",
                        self._code_retries + 1,
                        out_path.name,
                    )

        return saved

    def _unique_path(self, base_name: str) -> Path:
        """Return a path under corpus_dir that does not yet exist."""
        fpath = self.corpus_dir / base_name
        counter = 0
        while fpath.exists():
            counter += 1
            fpath = self.corpus_dir / f"{base_name}_{counter}"
        return fpath

    def _run_seed_code_with_retry(self, code: str, out_path: Path) -> Path | None:
        """
        Execute seed code; on failure ask the LLM to fix it and retry up to
        self._code_retries times.  Returns the output Path on success, None
        after all attempts fail (caller writes the safety fallback).
        """
        current_code = code
        for attempt in range(self._code_retries + 1):
            result, error_msg = self._run_seed_code(current_code, out_path)
            if result:
                if attempt > 0:
                    logger.info(
                        "Seed code succeeded on attempt %d/%d",
                        attempt + 1, self._code_retries + 1,
                    )
                return result

            if attempt >= self._code_retries:
                break

            provider = self._get_provider()
            if not provider:
                logger.warning("No LLM provider configured — cannot retry seed code fix")
                break

            logger.info(
                "Seed code failed (attempt %d/%d) — asking LLM to fix...",
                attempt + 1, self._code_retries + 1,
            )
            fixed = self._ask_llm_fix_code(current_code, error_msg)
            if not fixed:
                logger.warning("LLM returned no fixed code — aborting retries")
                break
            current_code = fixed

        return None

    def _ask_llm_fix_code(self, code: str, error_msg: str) -> str:
        """Ask the LLM to fix a broken seed-generation script. Returns the fixed code string."""
        provider = self._get_provider()
        if provider is None:
            return ""
        prompt = (
            "### Task\n"
            "Fix the Python seed-generation script below so it executes without errors "
            "and writes a binary file to OUTPUT_PATH.\n\n"
            "### Attachment\n"
            f"### Script\n{code}\n\n"
            f"### Error\n{error_msg}\n\n"
            "### Suggestion\n"
            "- OUTPUT_PATH is a pre-defined variable (absolute path string); "
            "write output with open(OUTPUT_PATH, 'wb')\n"
            "- os, struct, zlib, hashlib are pre-imported; do not re-import them\n"
            "- Add any other imports your fix requires\n"
            "- python3 -I isolation mode; standard library only\n\n"
            "### Answer Template\n"
            "Reply with ONLY the corrected Python script. No explanation. No markdown fences."
        )
        try:
            response = provider.generate(
                prompt=prompt,
                max_tokens=self._max_tokens,
                temperature=0.2,
            )
            code_text = response.strip()
            if code_text.startswith("```"):
                code_text = code_text.split("```", 1)[1]
                if code_text.startswith(("python\n", "py\n")):
                    code_text = code_text.split("\n", 1)[1]
                code_text = code_text.rsplit("```", 1)[0]
            return code_text.strip()
        except Exception as exc:
            logger.warning("LLM fix request failed: %s", exc)
            return ""

    def _run_seed_code(self, code: str, out_path: Path) -> tuple[Path | None, str]:
        """
        Execute a Python seed-generation script. Returns (output_path, error_msg).

        On success: (Path, ""). On failure: (None, description of the error).
        The script is kept in workspace/seed_code/ for manual inspection.

        Security hardening:
          - python3 -I  : isolated mode — ignores PYTHONPATH, site-packages tricks
          - minimal env : strips most environment variables to limit side-effects
        """
        import shutil
        import subprocess

        seed_code_dir = self.corpus_dir.parent / "seed_code"
        seed_code_dir.mkdir(parents=True, exist_ok=True)

        script_path = seed_code_dir / f"{out_path.name}.py"
        preamble = (
            f"# Auto-injected — write your output to OUTPUT_PATH, not a hardcoded filename.\n"
            f"import os, struct, zlib, hashlib  # common imports pre-loaded\n"
            f"OUTPUT_PATH = {str(out_path.resolve())!r}\n"
        )
        script_path.write_text(preamble + code)

        before = set(self.corpus_dir.iterdir())

        try:
            proc = subprocess.run(
                ["python3", "-I", str(script_path)],
                capture_output=True, text=True, timeout=30,
                cwd=str(seed_code_dir),
                env={"PATH": "/usr/bin:/bin:/usr/local/bin"},
            )
            if proc.returncode != 0:
                logger.warning(
                    "Seed code failed (rc=%d):\n%s\n  script: %s",
                    proc.returncode, proc.stderr, script_path,
                )
                return None, proc.stderr or f"Exit code {proc.returncode}"

            # Primary: script wrote to OUTPUT_PATH (corpus)
            if out_path.exists():
                logger.info(
                    "Wrote code-generated seed: %s (%d bytes)  [script: %s]",
                    out_path.name, out_path.stat().st_size, script_path,
                )
                return out_path, ""

            # Fallback: script wrote to a relative path that landed in seed_code_dir
            new_in_seed_code = [
                p for p in seed_code_dir.iterdir()
                if p.suffix != ".py" and p.is_file() and p.stat().st_size > 0
                and p not in before
            ]
            if new_in_seed_code:
                shutil.move(str(new_in_seed_code[0]), str(out_path))
                logger.info(
                    "Wrote code-generated seed (recovered from seed_code): %s (%d bytes)  [script: %s]",
                    out_path.name, out_path.stat().st_size, script_path,
                )
                return out_path, ""

            no_output_msg = (
                f"Script ran without error but produced no output file.\n"
                f"stdout: {proc.stdout[:500]}\nstderr: {proc.stderr[:500]}"
            )
            logger.warning(
                "Seed code ran but produced no output.\n  script: %s\n  stdout: %s\n  stderr: %s",
                script_path, proc.stdout[:500], proc.stderr[:500],
            )
            return None, no_output_msg
        except subprocess.TimeoutExpired:
            logger.warning("Seed code timed out  [script: %s]", script_path)
            return None, "Execution timed out after 30 seconds"
        except Exception as e:
            logger.error("Seed code execution error: %s  [script: %s]", e, script_path)
            return None, str(e)
