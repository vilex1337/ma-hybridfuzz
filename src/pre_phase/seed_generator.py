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

logger = logging.getLogger("pre_phase.seed_gen")


class SeedGenerator:
    def __init__(self, config: dict):
        self.config = config
        self.corpus_dir = Path(config["paths"]["corpus"])
        self.corpus_dir.mkdir(parents=True, exist_ok=True)

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
                result = self._run_seed_code(code, out_path)
                if result:
                    saved.append(result)

        return saved

    def _unique_path(self, base_name: str) -> Path:
        """Return a path under corpus_dir that does not yet exist."""
        fpath = self.corpus_dir / base_name
        counter = 0
        while fpath.exists():
            counter += 1
            fpath = self.corpus_dir / f"{base_name}_{counter}"
        return fpath

    def _run_seed_code(self, code: str, out_path: Path) -> Path | None:
        """
        Execute a Python seed-generation script and return the output path.

        Security hardening:
          - python3 -I  : isolated mode — ignores PYTHONPATH, site-packages tricks
          - minimal env : strips most environment variables to limit side-effects
          - separate cwd: script runs in a temporary directory, not the corpus dir
        """
        import subprocess
        import tempfile

        # Write script to temp file, injecting the output path as OUTPUT_PATH
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False
        ) as tmp:
            preamble = f"OUTPUT_PATH = {str(out_path)!r}\n"
            tmp.write(preamble + code)
            script_path = tmp.name

        try:
            proc = subprocess.run(
                ["python3", "-I", script_path],    # -I: isolated mode
                capture_output=True, text=True, timeout=30,
                cwd=tempfile.mkdtemp(),            # isolated working directory
                env={"PATH": "/usr/bin:/bin:/usr/local/bin"},  # minimal environment
            )
            if proc.returncode != 0:
                logger.warning(
                    "Seed code failed (rc=%d): %s", proc.returncode, proc.stderr[:200]
                )
                return None
            if out_path.exists():
                logger.info(
                    "Wrote code-generated seed: %s (%d bytes)",
                    out_path.name, out_path.stat().st_size,
                )
                return out_path
            logger.warning("Seed code ran but did not produce %s", out_path)
            return None
        except subprocess.TimeoutExpired:
            logger.warning("Seed code timed out for %s", out_path.name)
            return None
        except Exception as e:
            logger.error("Seed code execution error: %s", e)
            return None
        finally:
            Path(script_path).unlink(missing_ok=True)
