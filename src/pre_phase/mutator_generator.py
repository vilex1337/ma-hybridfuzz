"""
Mutator Generator - Creates bug-specific custom mutators for AFL++.
(Gap 3 - RANDLUZZ-inspired)
"""

import json
import logging
from pathlib import Path

import anthropic

logger = logging.getLogger("pre_phase.mutator_gen")

# Template for AFL++ custom mutator Python module
MUTATOR_TEMPLATE = '''"""Auto-generated custom mutator for AFL++: {name}"""

import struct
import random


def init(seed):
    random.seed(seed)


def fuzz(buf, add_buf, max_size):
    """Mutate input buffer. Returns mutated buffer."""
    buf = bytearray(buf)
    if len(buf) == 0:
        buf = bytearray(b"\\x00" * 64)

{mutation_logic}

    return bytes(buf[:max_size])


def describe(max_description_length):
    return b"{name}"[:max_description_length]
'''


class MutatorGenerator:
    def __init__(self, config: dict):
        self.config = config
        self.client = anthropic.Anthropic()
        self.model = config["llm"]["model"]
        self.mutator_dir = Path(config["paths"]["mutators"])
        self.mutator_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, analysis: dict, bug_type: str) -> list[Path]:
        """Generate bug-specific AFL++ custom mutators."""
        constraints = analysis.get("constraints", [])
        vuln_pattern = analysis.get("vulnerability_pattern", "")

        prompt = f"""You are creating custom mutation strategies for AFL++ directed fuzzing.

Bug type: {bug_type}
Vulnerability pattern: {vuln_pattern}
Input constraints: {json.dumps(constraints[:10])}

Generate 3-5 Python mutation functions for AFL++.
Each mutator should target the specific bug type.

For each mutator, provide:
- "name": descriptive name (alphanumeric + underscore only)
- "description": what it does
- "mutation_logic": Python code (indented with 4 spaces) that mutates `buf` (bytearray).
  The code should modify `buf` in-place. Available: `struct`, `random`, `len(buf)`.

Examples of mutation strategies:
- For buffer_overflow: extend buffer size, insert long strings at key offsets
- For use_after_free: manipulate sequence fields that control alloc/free ordering
- For integer_overflow: insert large integer values at numeric fields
- For format_string: insert format specifiers (%s, %n, %x)

Return a JSON object with key "mutators" containing the list.
Return ONLY valid JSON."""

        response = self.client.messages.create(
            model=self.model,
            max_tokens=self.config["llm"]["max_tokens"],
            temperature=self.config["llm"]["temperature"],
            messages=[{"role": "user", "content": prompt}],
        )

        mutators = self._parse_mutators(response.content[0].text)
        saved = self._save_mutators(mutators)
        return saved

    def _parse_mutators(self, text: str) -> list[dict]:
        try:
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0]
            elif "```" in text:
                text = text.split("```")[1].split("```")[0]
            data = json.loads(text.strip())
            return data.get("mutators", [])
        except (json.JSONDecodeError, IndexError) as e:
            logger.error("Failed to parse mutator response: %s", e)
            return []

    def _save_mutators(self, mutators: list[dict]) -> list[Path]:
        saved = []
        for mutator in mutators:
            name = mutator.get("name", "unknown_mutator")
            name = "".join(c for c in name if c.isalnum() or c == "_")
            logic = mutator.get("mutation_logic", "    pass")

            # Ensure proper indentation
            lines = logic.split("\n")
            indented = "\n".join(
                f"    {line}" if not line.startswith("    ") else line
                for line in lines
            )

            content = MUTATOR_TEMPLATE.format(name=name, mutation_logic=indented)
            fpath = self.mutator_dir / f"mutator_{name}.py"
            fpath.write_text(content)
            saved.append(fpath)
            logger.info("Saved mutator: %s", name)

        return saved
