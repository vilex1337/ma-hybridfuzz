"""
CFG Extractor — extracts basic blocks, call graph, and source line mappings
from C/C++ source via LLVM IR. Falls back to function-level if clang unavailable.
"""
import logging
import os
import re
import subprocess
import tempfile
from pathlib import Path

from config import AppConfig
from logging_utils import VERBOSE_LEVEL

logger = logging.getLogger("pre_phase.cfg_extractor")

_FUNC_DEF  = re.compile(r'^define\b.*?@(?:"([^"]+)"|([\w.$-]+))\s*\(')
_BB_LABEL  = re.compile(r"^(\w+):\s*(?:;.*)?$")
_DBG_REF   = re.compile(r"!dbg !(\d+)")
_CALL_INST = re.compile(r'\b(?:call|invoke)\b[^@]*@(?:"([^"]+)"|([\w.$-]+))\s*\(')
_DI_LOC    = re.compile(r"!(\d+) = (?:distinct )?!DILocation\(line: (\d+)")
_DI_FILE   = re.compile(r'!(\d+) = (?:distinct )?!DIFile\(filename: "([^"]+)"')
_DI_SUB    = re.compile(
    r'!(\d+) = (?:distinct )?!DISubprogram\(name: "([^"]+)"[^)]*?file: !(\d+)',
    re.DOTALL,
)
# Maps metadata id → demangled name and mangled linkageName respectively.
_DI_NAME   = re.compile(r'!(\d+) = (?:distinct )?!DISubprogram\([^)]*?name: "([^"]+)"', re.DOTALL)
_DI_LINK   = re.compile(r'!(\d+) = (?:distinct )?!DISubprogram\([^)]*?linkageName: "([^"]+)"', re.DOTALL)


class CFGExtractor:
    """Extract basic blocks and call graph from C/C++ source.

    Primary path: compiles each source file to LLVM IR with debug info and
    parses blocks + call edges from the IR text.
    Fallback: treats each heuristically-detected function as a single block.
    """

    def __init__(self, config: AppConfig | None = None):
        self.config = config
        self._file_lines: dict[str, list[str]] = {}

    def build_call_graph(self, source_dir: str) -> dict[str, set[str]]:
        """Return demangled call graph {func_name -> {callee_names}} from LLVM IR.

        Used by CallChainExtractor. Returns {} when clang is unavailable.
        """
        logger.log(VERBOSE_LEVEL, "[CFG] Building call graph from LLVM IR: source_dir=%s", source_dir)
        ll_files = self._compile_to_ir(Path(source_dir))
        if not ll_files:
            return {}
        _, cg = self._parse_ir_files(ll_files, Path(source_dir))
        logger.log(
            VERBOSE_LEVEL,
            "[CFG] Call graph complete: functions=%d edges=%d",
            len(cg),
            sum(len(v) for v in cg.values()),
        )
        return {f: set(callees) for f, callees in cg.items()}

    def extract(self, source_dir: str) -> tuple[dict, dict]:
        """Return (blocks, call_graph).

        blocks      : {bb_id -> {"func": str, "source": str}}
        call_graph  : {func_name -> [called_func_names]}
        """
        src = Path(source_dir)
        logger.log(VERBOSE_LEVEL, "[CFG] Extracting blocks and call graph: source_dir=%s", source_dir)
        ll_files = self._compile_to_ir(src)
        if ll_files:
            return self._parse_ir_files(ll_files, src)
        logger.warning("LLVM IR unavailable; using function-level fallback")
        return self._function_fallback(src)

    # ── LLVM IR ───────────────────────────────────────────────────────────────

    def _compile_to_ir(self, source_dir: Path) -> list[Path]:
        tmpdir = Path(tempfile.mkdtemp(prefix="hybridfuzz_ir_"))
        makefile_ir = self._compile_to_ir_with_makefile(source_dir, tmpdir)
        if makefile_ir:
            return makefile_ir

        ll_files: list[Path] = []
        source_files: list[Path] = []
        for ext in ("*.c", "*.cpp", "*.cc"):
            source_files.extend(source_dir.rglob(ext))
        logger.log(
            VERBOSE_LEVEL,
            "[CFG] IR build started: sources=%d output_dir=%s",
            len(source_files),
            tmpdir,
        )
        for src in source_files:
            out = tmpdir / f"{src.stem}_{src.parent.name}.ll"
            cmd = [
                "clang", "-S", "-emit-llvm", "-g", "-O0", "-w",
                "-o", str(out), str(src),
            ]
            try:
                r = subprocess.run(
                    cmd,
                    capture_output=True,
                    timeout=30,
                )
                if r.returncode == 0 and out.exists():
                    ll_files.append(out)
                    logger.log(
                        VERBOSE_LEVEL,
                        "[CFG] IR emitted: source=%s ll=%s",
                        src,
                        out,
                    )
                else:
                    stderr = (r.stderr or b"").decode(errors="ignore")[:200]
                    logger.log(
                        VERBOSE_LEVEL,
                        "[CFG] IR skipped: source=%s rc=%s stderr=%s",
                        src,
                        r.returncode,
                        stderr.strip(),
                    )
            except subprocess.TimeoutExpired:
                logger.log(VERBOSE_LEVEL, "[CFG] IR timed out: source=%s", src)
            except FileNotFoundError:
                logger.log(VERBOSE_LEVEL, "[CFG] clang not found while compiling %s", src)
                break
            except OSError as exc:
                logger.log(VERBOSE_LEVEL, "[CFG] IR OS error for %s: %s", src, exc)
        logger.log(
            VERBOSE_LEVEL,
            "[CFG] IR build complete: emitted=%d/%d",
            len(ll_files),
            len(source_files),
        )
        return ll_files

    def _compile_to_ir_with_makefile(self, source_dir: Path, output_dir: Path) -> list[Path]:
        """Build LLVM IR through the target Makefile when an `ir` target exists."""
        build_dir = self._makefile_build_dir(source_dir)
        if build_dir is None:
            return []

        logger.log(
            VERBOSE_LEVEL,
            "[CFG] Makefile IR build started: cwd=%s output_dir=%s",
            build_dir,
            output_dir,
        )
        target_cfg = self.config.target if self.config else None
        env = {
            **os.environ,
            "CC": target_cfg.ir_cc if target_cfg else "clang",
            "CXX": target_cfg.ir_cxx if target_cfg else "clang++",
            "IR_DIR": str(output_dir),
        }
        extra_flags = target_cfg.ir_compile_flags if target_cfg else []
        if extra_flags:
            flags = " ".join(extra_flags)
            env["CFLAGS"] = (env.get("CFLAGS", "") + " " + flags).strip()
            env["CXXFLAGS"] = (env.get("CXXFLAGS", "") + " " + flags).strip()

        ir_timeout = target_cfg.ir_build_timeout if target_cfg else 300
        try:
            result = subprocess.run(
                ["make", "ir"],
                cwd=build_dir,
                env=env,
                capture_output=True,
                text=True,
                timeout=ir_timeout,
            )
        except FileNotFoundError:
            logger.log(VERBOSE_LEVEL, "[CFG] Makefile IR skipped: make not found")
            return []
        except subprocess.TimeoutExpired:
            logger.warning("[CFG] Makefile IR build timed out after %ds", ir_timeout)
            return []
        except OSError as exc:
            logger.warning("[CFG] Makefile IR build OS error: %s", exc)
            return []

        ll_files = sorted(output_dir.rglob("*.ll"))
        if result.returncode != 0:
            logger.log(
                VERBOSE_LEVEL,
                "[CFG] Makefile IR build failed: cwd=%s rc=%d stderr=%s",
                build_dir,
                result.returncode,
                (result.stderr or "")[:500].strip(),
            )
            return []
        if not ll_files:
            logger.log(
                VERBOSE_LEVEL,
                "[CFG] Makefile IR build produced no .ll files: stdout=%s",
                (result.stdout or "")[:500].strip(),
            )
            return []

        logger.log(
            VERBOSE_LEVEL,
            "[CFG] Makefile IR build complete: emitted=%d",
            len(ll_files),
        )
        return ll_files

    def _makefile_build_dir(self, source_dir: Path) -> Path | None:
        target_cfg = self.config.target if self.config else None
        candidates = []
        for value in (
            (target_cfg.ir_build_dir if target_cfg else ""),
            (target_cfg.build_dir if target_cfg else ""),
        ):
            if value:
                candidates.append(Path(value))
        candidates.append(source_dir)

        for candidate in candidates:
            if (candidate / "Makefile").exists():
                return candidate
        return None

    def _parse_ir_files(self, ll_files: list[Path], source_dir: Path) -> tuple[dict, dict]:
        all_blocks: dict = {}
        raw_cg: dict[str, set] = {}
        logger.log(VERBOSE_LEVEL, "[CFG] Parsing LLVM IR files: count=%d", len(ll_files))
        for ll in ll_files:
            blocks, cg = self._parse_single_ir(ll.read_text(errors="ignore"), source_dir)
            all_blocks.update(blocks)
            for f, callees in cg.items():
                raw_cg.setdefault(f, set()).update(callees)
            logger.log(
                VERBOSE_LEVEL,
                "[CFG] Parsed IR: file=%s blocks=%d functions=%d edges=%d",
                ll.name,
                len(blocks),
                len(cg),
                sum(len(v) for v in cg.values()),
            )
        call_graph = {f: list(c) for f, c in raw_cg.items()}
        logger.log(
            VERBOSE_LEVEL,
            "[CFG] IR parse complete: total_blocks=%d total_functions=%d total_edges=%d",
            len(all_blocks),
            len(call_graph),
            sum(len(v) for v in call_graph.values()),
        )
        return all_blocks, call_graph

    def _build_name_map(self, text: str) -> dict[str, str]:
        """Build mangled-IR-symbol → demangled-source-name from !DISubprogram metadata."""
        id_to_src  = {m.group(1): m.group(2) for m in _DI_NAME.finditer(text)}
        id_to_link = {m.group(1): m.group(2) for m in _DI_LINK.finditer(text)}
        return {
            id_to_link[i]: id_to_src[i]
            for i in id_to_link
            if i in id_to_src and id_to_link[i] != id_to_src[i]
        }

    def _parse_single_ir(self, text: str, source_dir: Path) -> tuple[dict, dict]:
        name_map = self._build_name_map(text)
        dbg_line = {m.group(1): int(m.group(2)) for m in _DI_LOC.finditer(text)}

        file_paths: dict[str, str] = {}
        for m in _DI_FILE.finditer(text):
            hits = list(source_dir.rglob(Path(m.group(2)).name))
            file_paths[m.group(1)] = str(hits[0]) if hits else m.group(2)

        func_file: dict[str, str] = {
            m.group(2): file_paths.get(m.group(3), "")
            for m in _DI_SUB.finditer(text)
        }

        blocks: dict = {}
        call_graph: dict[str, set] = {}
        cur_func: str | None = None
        cur_bb: str | None = None
        cur_lines: list[str] = []
        bb_idx = 0

        for raw in text.split("\n"):
            s = raw.strip()

            fm = _FUNC_DEF.match(s)
            if fm:
                if cur_bb and cur_lines:
                    blocks[cur_bb] = {"func": cur_func, "source": "\n".join(cur_lines)}
                symbol = fm.group(1) or fm.group(2)
                func_name: str = name_map.get(symbol, symbol)
                cur_func = func_name
                call_graph.setdefault(func_name, set())
                bb_idx = 0
                cur_bb = f"{func_name}_bb0"
                cur_lines = []
                continue

            if s == "}":
                if cur_bb and cur_lines:
                    blocks[cur_bb] = {"func": cur_func, "source": "\n".join(cur_lines)}
                cur_func = cur_bb = None
                cur_lines = []
                continue

            if cur_func is None:
                continue

            lm = _BB_LABEL.match(s)
            if lm and s not in ("{", "}"):
                if cur_bb and cur_lines:
                    blocks[cur_bb] = {"func": cur_func, "source": "\n".join(cur_lines)}
                bb_idx += 1
                cur_bb = f"{cur_func}_bb{bb_idx}"
                cur_lines = []
                continue

            dm = _DBG_REF.search(s)
            if dm:
                dbg_id = dm.group(1)
                if dbg_id in dbg_line:
                    src_text = self._source_line(
                        func_file.get(cur_func, ""), dbg_line[dbg_id]
                    )
                    if src_text and src_text not in cur_lines:
                        cur_lines.append(src_text)

            cm = _CALL_INST.search(s)
            if cm and cur_func:
                symbol = cm.group(1) or cm.group(2)
                callee = name_map.get(symbol, symbol)
                if not callee.startswith("llvm.") and not callee.startswith("__"):
                    call_graph[cur_func].add(callee)

        return blocks, call_graph

    def _source_line(self, filepath: str, line_no: int) -> str:
        if not filepath:
            return ""
        if filepath not in self._file_lines:
            try:
                self._file_lines[filepath] = (
                    Path(filepath).read_text(errors="ignore").splitlines()
                )
            except OSError:
                self._file_lines[filepath] = []
        lines = self._file_lines[filepath]
        if 1 <= line_no <= len(lines):
            return lines[line_no - 1].strip()
        return ""

    # ── Fallback ──────────────────────────────────────────────────────────────

    def _function_fallback(self, source_dir: Path) -> tuple[dict, dict]:
        blocks: dict = {}
        files_scanned = 0
        for ext in ("*.c", "*.cpp", "*.cc"):
            for fpath in source_dir.rglob(ext):
                files_scanned += 1
                try:
                    content = fpath.read_text(errors="ignore")
                    for name, body in _heuristic_functions(content).items():
                        blocks[f"{name}_bb0"] = {"func": name, "source": body[:2000]}
                except OSError:
                    pass
        logger.log(
            VERBOSE_LEVEL,
            "[CFG] Function-level fallback complete: files=%d functions=%d",
            files_scanned,
            len(blocks),
        )
        return blocks, {}


def _heuristic_functions(content: str) -> dict[str, str]:
    """Heuristic C/C++ function extractor (same logic as old AttentionComputer)."""
    functions: dict[str, str] = {}
    lines = content.split("\n")
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        if (
            "(" in line and ")" in line and "{" in line
            and not line.startswith(("//", "#", "if", "while", "for", "switch"))
        ):
            before_paren = line.split("(")[0].strip()
            parts = before_paren.split()
            if parts:
                name = parts[-1].lstrip("*&")
                if name and name.isidentifier():
                    depth = line.count("{") - line.count("}")
                    body_lines = [lines[i]]
                    j = i + 1
                    while j < len(lines) and depth > 0:
                        body_lines.append(lines[j])
                        depth += lines[j].count("{") - lines[j].count("}")
                        j += 1
                    body = "\n".join(body_lines)
                    if len(body) < 5000:
                        functions[name] = body
                    i = j
                    continue
        i += 1
    return functions
