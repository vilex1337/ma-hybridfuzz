"""
AFL++ Runner - Manages AFL++ instrumentation and execution.
"""

import logging
import os
import signal
import subprocess
from pathlib import Path

from config import AppConfig
from logging_utils import VERBOSE_LEVEL

logger = logging.getLogger("fuzzing.afl_runner")


class AFLRunner:
    def __init__(self, config: AppConfig):
        self.config = config
        self._process = None
        self._output_dir = None
        self.canary_storage_path: str | None = None

    def instrument(self, binary: str, source_dir: str, use_asan: bool = True) -> str:
        """Compile and instrument the target binary with AFL++."""
        from pre_phase.binary_builder import build_binary

        binary_path = Path(binary)
        instrumented_path = f"/workspace/instrumented/{binary_path.stem}_instrumented"

        afl_env = {
            "AFL_USE_ASAN": "1" if use_asan else "0",
        }
        if self.config.fuzzer.use_ubsan:
            afl_env["AFL_USE_UBSAN"] = "1"

        # Magma canary instrumentation (reach/trigger tracking, see canary_reader.py).
        # -include canary.h is harmless even when MAGMA_ENABLE_CANARIES is unset (it
        # only declares macros); the bug patches gate the actual MAGMA_LOG call sites
        # behind #ifdef MAGMA_ENABLE_CANARIES.
        canary_h = Path("/magma_src/canary.h")
        extra_cflags = ["-include", str(canary_h), "-DMAGMA_ENABLE_CANARIES"] if canary_h.exists() else []

        logger.log(
            VERBOSE_LEVEL,
            "[AFLRunner] Instrumentation requested: binary=%s source_dir=%s output=%s env=%s canary=%s",
            binary,
            source_dir,
            instrumented_path,
            afl_env,
            bool(extra_cflags),
        )

        ok = build_binary(
            source_dir,
            instrumented_path,
            "afl-clang-fast",
            "afl-clang-fast++",
            binary_path.stem,
            env=afl_env,
            extra_cflags=extra_cflags,
        )
        if not ok:
            raise RuntimeError(f"AFL++ instrumentation failed for {binary}")

        logger.info("Instrumented binary: %s", instrumented_path)
        return instrumented_path

    def start(
        self,
        instrumented_binary: str,
        corpus_dir: str,
        crashes_dir: str,
        mutator_dir: str,
        scheduler=None,
    ):
        """Start AFL++ fuzzing session."""
        self._output_dir = crashes_dir
        logger.log(
            VERBOSE_LEVEL,
            "[AFLRunner] Initializing fuzzer: binary=%s corpus=%s output=%s mutator_dir=%s scheduler=%s",
            instrumented_binary,
            corpus_dir,
            crashes_dir,
            mutator_dir,
            type(scheduler).__name__ if scheduler else None,
        )

        # Environment variables AFL++ needs in containerised / restricted
        # environments. Without these the fuzzer prints a warning and exits
        # immediately on most distros.
        env = os.environ.copy()
        env.setdefault("AFL_SKIP_CPUFREQ", "1")             # skip governor check
        env.setdefault("AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES", "1")  # skip core_pattern exit
        env.setdefault("AFL_NO_AFFINITY", "1")              # skip CPU binding in containers
        env.setdefault("AFL_AUTORESUME", "1")               # resume instead of refusing non-empty out
        # ASAN sometimes reports false leaks at exit; disabling that reduces noise.
        env.setdefault("ASAN_OPTIONS", "abort_on_error=1:symbolize=0:detect_leaks=0")

        # Magma canary storage (reach/trigger tracking, see canary_reader.py).
        # Only meaningful if the binary was instrumented with MAGMA_ENABLE_CANARIES
        # (i.e. /magma_src/canary.h existed at instrument() time) and the CVE
        # config declares target.magma_bug_id.
        if self.config.target.magma_bug_id:
            from benchmark.canary_reader import init_canary_storage
            self.canary_storage_path = str(Path(self.config.paths.coverage) / "canary.raw")
            init_canary_storage(self.canary_storage_path)
            env["MAGMA_STORAGE"] = self.canary_storage_path
            logger.info("Magma canary storage: %s (bug_id=%s)", self.canary_storage_path, self.config.target.magma_bug_id)
        else:
            self.canary_storage_path = None

        # Build AFL++ command
        # ASAN reserves large virtual address ranges; a hard memory cap causes
        # the forkserver to crash before any input is processed.
        mem = "none" if self.config.fuzzer.use_asan else str(self.config.fuzzer.memory_limit)
        cmd = [
            "afl-fuzz",
            "-i", corpus_dir,
            "-o", crashes_dir,
            "-t", str(self.config.fuzzer.exec_timeout),
            "-m", mem,
        ]

        # Add custom mutator if available and enabled
        mutator_files = list(Path(mutator_dir).glob("mutator_*.so"))
        if mutator_files and self.config.fuzzer.use_custom_mutator:
            env["AFL_CUSTOM_MUTATOR_LIBRARY"] = ";".join(str(f) for f in mutator_files)
            logger.info("Using custom mutator libraries: %s", [f.name for f in mutator_files])

        # Pass AFLGo-format distance file if available (written by AttentionDistanceComputer)
        dist_cfg = Path(self.config.paths.distance_cache) / "distance.cfg.txt"
        if dist_cfg.exists():
            env["AFL_LLVM_AFLGO_INST_RATIO"] = "100"
            env["AFL_CUSTOM_INFO_OUT"] = str(dist_cfg)
            logger.info("Using attention distance file: %s", dist_cfg)

        # Power schedule - use attention-guided if scheduler available
        if scheduler and scheduler.has_distance_matrix():
            cmd.extend(["-p", "exploit"])
            distance_file = scheduler.export_afl_distance_file()
            if distance_file:
                env["AFL_DISTANCE_FILE"] = distance_file
            logger.log(
                VERBOSE_LEVEL,
                "[AFLRunner] Scheduler mode: attention-guided distance_file=%s",
                distance_file,
            )
        else:
            cmd.extend(["-p", "fast"])
            logger.log(VERBOSE_LEVEL, "[AFLRunner] Scheduler mode: AFL fast")

        cmd.extend(["--", instrumented_binary, "@@"])
        logger.log(
            VERBOSE_LEVEL,
            "[AFLRunner] AFL environment: AFL_CUSTOM_MUTATOR_LIBRARY=%s AFL_DISTANCE_FILE=%s ASAN_OPTIONS=%s",
            env.get("AFL_CUSTOM_MUTATOR_LIBRARY", ""),
            env.get("AFL_DISTANCE_FILE", ""),
            env.get("ASAN_OPTIONS", ""),
        )

        # Stream AFL++ stdout+stderr to a log file so we can see why it
        # died (e.g. bad core_pattern, calibration failure, bad instrumentation).
        log_path = Path(self.config.paths.logs) / "afl_fuzz.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        self._afl_log = open(log_path, "w")
        logger.info("AFL++ output → %s", log_path)
        logger.info("Starting AFL++: %s", " ".join(cmd))
        try:
            self._process = subprocess.Popen(
                cmd,
                stdout=self._afl_log,
                stderr=subprocess.STDOUT,
                env=env,
            )
        except FileNotFoundError:
            self._afl_log.close()
            raise RuntimeError("afl-fuzz not found in PATH") from None
        except OSError as exc:
            self._afl_log.close()
            raise RuntimeError(f"Failed to start afl-fuzz: {exc}") from exc
        logger.info("AFL++ started with PID %d", self._process.pid)

    def stop(self):
        """Stop the AFL++ process."""
        if self._process:
            rc = self._process.poll()
            if rc is not None:
                logger.warning(
                    "AFL++ already exited before stop() (rc=%d). Check afl_fuzz.log.", rc,
                )
            else:
                logger.info("Stopping AFL++ (PID %d)...", self._process.pid)
                self._process.send_signal(signal.SIGINT)
                try:
                    self._process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    self._process.kill()
                    self._process.wait()
            logger.info("AFL++ stopped (rc=%d)", self._process.returncode)
        if getattr(self, "_afl_log", None):
            self._afl_log.close()
        self._make_output_readable()

    def get_stats(self) -> dict | None:
        """Read AFL++ fuzzer_stats file."""
        if not self._output_dir:
            return None

        # Early warning if the fuzzer died
        if self._process is not None and self._process.poll() is not None:
            logger.error(
                "AFL++ exited unexpectedly with rc=%d. See %s for details.",
                self._process.returncode,
                Path(self.config.paths.logs) / "afl_fuzz.log",
            )
            return None

        return self._read_stats_file()

    def _read_stats_file(self) -> dict | None:
        if not self._output_dir:
            logger.debug("Cannot find: %s", self._output_dir)
            return None
        stats_path = Path(self._output_dir) / "default" / "fuzzer_stats"
        if not stats_path.exists():
            # Try alternate path
            stats_path = Path(self._output_dir) / "fuzzer_stats"
        if not stats_path.exists():
            logger.debug("Cannot find: %s", stats_path)
            return None

        stats = {}
        try:
            for line in stats_path.read_text().strip().split("\n"):
                if ":" in line:
                    key, val = line.split(":", 1)
                    stats[key.strip()] = val.strip()
        except Exception as e:
            logger.debug("Could not read stats: %s", e)
            return None

        # Modern AFL++ writes saved_crashes/saved_hangs instead of the
        # AFL-classic unique_crashes/unique_hangs field names.
        if "unique_crashes" not in stats and "saved_crashes" in stats:
            stats["unique_crashes"] = stats["saved_crashes"]
        if "unique_hangs" not in stats and "saved_hangs" in stats:
            stats["unique_hangs"] = stats["saved_hangs"]

        # Convert numeric fields
        for field in ("corpus_count", "unique_crashes", "unique_hangs", "execs_done"):
            if field in stats:
                try:
                    stats[field] = int(stats[field])
                except ValueError:
                    pass

        return stats

    def _make_output_readable(self) -> None:
        """Relax AFL++ output permissions so bind-mounted workspaces are inspectable."""
        if not self._output_dir:
            return
        output_dir = Path(self._output_dir)
        if not output_dir.exists():
            return
        try:
            for path in output_dir.rglob("*"):
                try:
                    if path.is_dir():
                        path.chmod(0o755)
                    else:
                        path.chmod(0o644)
                except OSError:
                    logger.debug("Could not chmod AFL output path: %s", path)
            output_dir.chmod(0o755)
            logger.info("AFL++ output made host-readable: %s", output_dir)
        except OSError as exc:
            logger.warning("Could not make AFL++ output host-readable: %s", exc)
