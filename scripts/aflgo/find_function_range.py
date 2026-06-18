#!/usr/bin/env python3
"""Locate a C function definition in a source tree and print AFLGo BBtargets
lines ("relative/path.c:N") for every line in its body.

AFLGo matches BBtargets.txt entries against the exact source line recorded in
each instrumented basic block's debug info, so a single guessed line is
unreliable. Emitting every line of the function body maximizes the chance
that at least one entry lands on a real basic block.

Usage: find_function_range.py <src_dir> <function_name>
"""
import re
import sys
from pathlib import Path

SKIP_DIRS = {".git", "test", "tests", "testcases", "docs", "contrib"}

DEF_RE = re.compile(r'(?<![\w.>])(?:\*\s*)?{func}\s*\(')


def find_definition(src_dir: Path, func: str):
    pattern = DEF_RE.pattern.format(func=re.escape(func))
    regex = re.compile(pattern)
    for path in sorted(src_dir.rglob("*.c")):
        if any(part in SKIP_DIRS for part in path.relative_to(src_dir).parts):
            continue
        try:
            lines = path.read_text(errors="ignore").splitlines()
        except OSError:
            continue
        for i, line in enumerate(lines):
            if not regex.search(line):
                continue
            # Walk forward from the match to find either a defining '{' or a
            # declaration-terminating ';' before any '{'.
            j = i
            brace_start = None
            while j < len(lines):
                if ";" in lines[j] and "{" not in lines[j][: lines[j].find(";") + 1]:
                    brace_start = None
                    break
                if "{" in lines[j]:
                    brace_start = j
                    break
                j += 1
            if brace_start is None:
                continue
            depth = 0
            k = brace_start
            while k < len(lines):
                depth += lines[k].count("{") - lines[k].count("}")
                if depth <= 0 and k > brace_start:
                    return path, i + 1, k + 1
                if depth <= 0 and k == brace_start and lines[k].count("}"):
                    return path, i + 1, k + 1
                k += 1
    return None


def main():
    if len(sys.argv) != 3:
        print("Usage: {} <src_dir> <function_name>".format(sys.argv[0]), file=sys.stderr)
        sys.exit(1)
    src_dir = Path(sys.argv[1]).resolve()
    func = sys.argv[2]

    result = find_definition(src_dir, func)
    if result is None:
        print("error: could not locate definition of '{}' under {}".format(func, src_dir),
              file=sys.stderr)
        sys.exit(1)

    path, start, end = result
    rel = path.relative_to(src_dir)
    for line_no in range(start, end + 1):
        print("{}:{}".format(rel, line_no))


if __name__ == "__main__":
    main()
