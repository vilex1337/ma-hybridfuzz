"""
Shared binary compilation utility for the pre-phase.

Both the AFL++ fuzzing binary and the LLVM coverage binary are built from
the same source tree with different compilers/flags.  This module provides
the common build-system detection logic so each instrumentation path only
needs to supply its own compiler and flags.

Build system detection order: CMake > Makefile > single-file.
"""

import logging
import os
import shutil
import subprocess
from pathlib import Path

from logging_utils import VERBOSE_LEVEL

logger = logging.getLogger("pre_phase.binary_builder")

_COMPILE_TIMEOUT = 1200  # seconds (large targets like php/openssl need >300s)


def build_binary(
    source_dir: str,
    out_binary: str,
    cc: str,
    cxx: str,
    binary_name: str,
    env: dict | None = None,
    extra_cflags: list[str] | None = None,
) -> bool:
    """
    Compile *source_dir* into *out_binary* using *cc*/*cxx*.

    *binary_name* is the executable name to locate after a CMake/Makefile
    build and copy to *out_binary*.  For single-file builds it is unused.

    *env* is merged on top of ``os.environ``; CC and CXX are always set.
    *extra_cflags* are injected as CFLAGS/CXXFLAGS env vars and, for CMake,
    as CMAKE_C_FLAGS / CMAKE_CXX_FLAGS.
    """
    source_path = Path(source_dir)
    if not source_path.exists():
        logger.error("[Builder] source_dir not found: %s", source_dir)
        return False

    build_env = {**os.environ, **(env or {})}
    build_env["CC"] = cc
    build_env["CXX"] = cxx

    flags_str = " ".join(extra_cflags) if extra_cflags else ""
    if flags_str:
        build_env["CFLAGS"] = (build_env.get("CFLAGS", "") + " " + flags_str).strip()
        build_env["CXXFLAGS"] = (build_env.get("CXXFLAGS", "") + " " + flags_str).strip()

    ncpus = str(os.cpu_count() or 1)
    logger.log(
        VERBOSE_LEVEL,
        "[Builder] Initializing build: source_dir=%s out=%s cc=%s cxx=%s binary_name=%s flags=%s",
        source_path,
        out_binary,
        cc,
        cxx,
        binary_name,
        flags_str or "<none>",
    )

    if (source_path / "CMakeLists.txt").exists():
        logger.log(VERBOSE_LEVEL, "[Builder] Detected build system: cmake")
        return _cmake_build(source_path, out_binary, cc, cxx, binary_name, build_env, flags_str, ncpus)
    if (source_path / "Makefile").exists():
        logger.log(VERBOSE_LEVEL, "[Builder] Detected build system: make")
        return _make_build(source_path, out_binary, binary_name, build_env, ncpus)
    logger.log(VERBOSE_LEVEL, "[Builder] Detected build system: single-file")
    return _single_file_build(source_path, out_binary, cc, cxx, extra_cflags or [], build_env)


# ── private helpers ──────────────────────────────────────────────────────────

def _cmake_build(source_path, out_binary, cc, cxx, binary_name, env, flags_str, ncpus) -> bool:
    build_dir = source_path / "build_instrumented"
    build_dir.mkdir(exist_ok=True)
    cmake_cmd = ["cmake", "..", f"-DCMAKE_C_COMPILER={cc}", f"-DCMAKE_CXX_COMPILER={cxx}"]
    if flags_str:
        cmake_cmd += [f"-DCMAKE_C_FLAGS={flags_str}", f"-DCMAKE_CXX_FLAGS={flags_str}"]
    logger.log(VERBOSE_LEVEL, "[Builder] CMake configure: cwd=%s cmd=%s", build_dir, " ".join(cmake_cmd))
    try:
        subprocess.run(cmake_cmd, cwd=build_dir, env=env, check=True,
                       capture_output=True, text=True, timeout=_COMPILE_TIMEOUT)
        logger.log(VERBOSE_LEVEL, "[Builder] CMake build: cwd=%s cmd=make -j%s", build_dir, ncpus)
        subprocess.run(["make", f"-j{ncpus}"], cwd=build_dir, env=env, check=True,
                       capture_output=True, text=True, timeout=_COMPILE_TIMEOUT)
    except FileNotFoundError as exc:
        logger.error("[Builder] cmake/make not found: %s", exc)
        return False
    except subprocess.CalledProcessError as exc:
        logger.error("[Builder] cmake build failed (rc=%d):\n%s", exc.returncode, (exc.stderr or "")[:500])
        return False
    except subprocess.TimeoutExpired:
        logger.error("[Builder] cmake build timed out after %ds", _COMPILE_TIMEOUT)
        return False
    return _find_and_copy(build_dir, binary_name, out_binary)


def _make_build(source_path, out_binary, binary_name, env, ncpus) -> bool:
    logger.log(VERBOSE_LEVEL, "[Builder] Make build: cwd=%s cmd=make -j%s", source_path, ncpus)
    try:
        subprocess.run(
            ["make", f"-j{ncpus}"],
            cwd=source_path, env=env, check=True,
            capture_output=True, text=True, timeout=_COMPILE_TIMEOUT,
        )
    except FileNotFoundError:
        logger.error("[Builder] make not found in PATH")
        return False
    except subprocess.CalledProcessError as exc:
        logger.error("[Builder] make failed (rc=%d):\n%s", exc.returncode, (exc.stderr or "")[:500])
        return False
    except subprocess.TimeoutExpired:
        logger.error("[Builder] make timed out after %ds", _COMPILE_TIMEOUT)
        return False
    return _find_and_copy(source_path, binary_name, out_binary)


def _single_file_build(source_path, out_binary, cc, cxx, extra_cflags, env) -> bool:
    sources: list[str] = []
    for ext in ("*.c", "*.cpp", "*.cc", "*.cxx"):
        sources.extend(str(p) for p in source_path.rglob(ext))
    if not sources:
        logger.error("[Builder] No C/C++ sources found in %s", source_path)
        return False

    has_cxx = any(Path(s).suffix in (".cpp", ".cc", ".cxx") for s in sources)
    compiler = cxx if has_cxx else cc
    cmd = [compiler, *extra_cflags, "-o", out_binary, *sources]

    os.makedirs(os.path.dirname(os.path.abspath(out_binary)), exist_ok=True)
    logger.info("[Builder] Compiling: %s ...", " ".join(cmd[:5]))
    try:
        r = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=_COMPILE_TIMEOUT)
    except FileNotFoundError:
        logger.error("[Builder] Compiler not found: %s", compiler)
        return False
    except subprocess.TimeoutExpired:
        logger.error("[Builder] Compilation timed out after %ds", _COMPILE_TIMEOUT)
        return False
    except OSError as exc:
        logger.error("[Builder] Compilation OS error: %s", exc)
        return False
    if r.returncode != 0:
        logger.error("[Builder] Compilation failed:\n%s", r.stderr[:500])
        return False
    os.chmod(out_binary, 0o755)
    return True


def _find_and_copy(search_dir: Path, binary_name: str, dest: str) -> bool:
    logger.log(
        VERBOSE_LEVEL,
        "[Builder] Locating built binary: search_dir=%s binary_name=%s",
        search_dir,
        binary_name,
    )
    for f in search_dir.rglob(binary_name):
        if f.is_file() and os.access(f, os.X_OK):
            os.makedirs(os.path.dirname(os.path.abspath(dest)), exist_ok=True)
            shutil.copy2(f, dest)
            os.chmod(dest, 0o755)
            logger.info("[Builder] Binary copied to %s", dest)
            return True
    logger.error("[Builder] Built binary '%s' not found under %s", binary_name, search_dir)
    return False
