"""
AFL++ Runner - Manages AFL++ instrumentation and execution.
"""

import json
import logging
import os
import shutil
import signal
import subprocess
from pathlib import Path

logger = logging.getLogger("fuzzing.afl_runner")


class AFLRunner:
    def __init__(self, config: dict):
        self.config = config
        self._process = None
        self._output_dir = None

    def instrument(self, binary: str, source_dir: str, use_asan: bool = True) -> str:
        """Compile and instrument the target binary with AFL++."""
        source_path = Path(source_dir)
        binary_path = Path(binary)

        # Determine compiler
        cc = "afl-clang-fast"
        cxx = "afl-clang-fast++"

        env = os.environ.copy()
        env["CC"] = cc
        env["CXX"] = cxx
        env["AFL_USE_ASAN"] = "1" if use_asan else "0"
        if self.config["fuzzer"].get("use_ubsan"):
            env["AFL_USE_UBSAN"] = "1"

        instrumented_path = f"/workspace/instrumented/{binary_path.stem}_instrumented"
        os.makedirs(os.path.dirname(instrumented_path), exist_ok=True)

        # Check if there's a Makefile or CMakeLists.txt
        makefile = source_path / "Makefile"
        cmake = source_path / "CMakeLists.txt"

        if cmake.exists():
            build_dir = source_path / "build_afl"
            build_dir.mkdir(exist_ok=True)
            subprocess.run(
                ["cmake", "..", f"-DCMAKE_C_COMPILER={cc}", f"-DCMAKE_CXX_COMPILER={cxx}"],
                cwd=build_dir, env=env, check=True,
            )
            subprocess.run(["make", "-j$(nproc)"], cwd=build_dir, env=env, shell=True, check=True)
            # Find the built binary
            for f in build_dir.rglob(binary_path.stem):
                if f.is_file() and os.access(f, os.X_OK):
                    shutil.copy2(f, instrumented_path)
                    break
        elif makefile.exists():
            subprocess.run(
                ["make", f"CC={cc}", f"CXX={cxx}", "-j$(nproc)"],
                cwd=source_path, env=env, shell=True, check=True,
            )
            built = source_path / binary_path.name
            if built.exists():
                shutil.copy2(built, instrumented_path)
        else:
            # Single file compilation
            source_files = list(source_path.glob("*.c")) + list(source_path.glob("*.cpp"))
            if not source_files:
                raise FileNotFoundError(f"No source files found in {source_dir}")

            compiler = cxx if any(f.suffix == ".cpp" for f in source_files) else cc
            cmd = [compiler, "-o", instrumented_path, "-g"]
            if use_asan:
                cmd.append("-fsanitize=address")
            cmd.extend(str(f) for f in source_files)

            logger.info("Compiling: %s", " ".join(cmd))
            subprocess.run(cmd, env=env, check=True)

        os.chmod(instrumented_path, 0o755)
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

        # Build AFL++ command
        cmd = [
            "afl-fuzz",
            "-i", corpus_dir,
            "-o", crashes_dir,
            "-t", str(self.config["fuzzer"]["exec_timeout"]),
            "-m", str(self.config["fuzzer"]["memory_limit"]),
        ]

        # Add custom mutator if available
        mutator_files = list(Path(mutator_dir).glob("mutator_*.py"))
        if mutator_files:
            # Use the first mutator as primary
            env_mutator = str(mutator_files[0])
            env["AFL_CUSTOM_MUTATOR_LIBRARY"] = ""
            env["AFL_PYTHON_MODULE"] = env_mutator
            logger.info("Using custom mutator: %s", env_mutator)

        # Power schedule - use attention-guided if scheduler available
        if scheduler and scheduler.has_distance_matrix():
            cmd.extend(["-p", "exploit"])
            # Write distance file for AFL++ if supported
            distance_file = scheduler.export_afl_distance_file()
            if distance_file:
                env["AFL_DISTANCE_FILE"] = distance_file
        else:
            cmd.extend(["-p", "fast"])

        cmd.extend(["--", instrumented_binary, "@@"])

        # Stream AFL++ stdout+stderr to a log file so we can see why it
        # died (e.g. bad core_pattern, calibration failure, bad instrumentation).
        log_path = Path(self.config["paths"]["logs"]) / "afl_fuzz.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        self._afl_log = open(log_path, "w")
        logger.info("AFL++ output → %s", log_path)
        logger.info("Starting AFL++: %s", " ".join(cmd))
        self._process = subprocess.Popen(
            cmd,
            stdout=self._afl_log,
            stderr=subprocess.STDOUT,
            env=env,
        )
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

    def get_stats(self) -> dict | None:
        """Read AFL++ fuzzer_stats file."""
        if not self._output_dir:
            return None

        # Early warning if the fuzzer died
        if self._process is not None and self._process.poll() is not None:
            logger.error(
                "AFL++ exited unexpectedly with rc=%d. See %s for details.",
                self._process.returncode,
                Path(self.config["paths"]["logs"]) / "afl_fuzz.log",
            )
            return None

        stats_path = Path(self._output_dir) / "default" / "fuzzer_stats"
        if not stats_path.exists():
            # Try alternate path
            stats_path = Path(self._output_dir) / "fuzzer_stats"
        if not stats_path.exists():
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

        # Convert numeric fields
        for field in ("paths_total", "unique_crashes", "unique_hangs"):
            if field in stats:
                try:
                    stats[field] = int(stats[field])
                except ValueError:
                    pass

        return stats
