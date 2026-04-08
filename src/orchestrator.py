"""
MA-HybridFuzz Orchestrator
Coordinates the full pipeline: Pre-phase -> Fuzzing Loop -> On-demand Reassessment
"""

import argparse
import logging
import os
import signal
import sys
import time
from pathlib import Path

import yaml

from pre_phase.reasoning_agent import ReasoningAgent
from pre_phase.seed_generator import SeedGenerator
from pre_phase.mutator_generator import MutatorGenerator
from pre_phase.attention_computer import AttentionComputer
from fuzzing.afl_runner import AFLRunner
from fuzzing.scheduler import AttentionScheduler

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("/workspace/logs/orchestrator.log"),
    ],
)
logger = logging.getLogger("orchestrator")


class Orchestrator:
    def __init__(self, config_path: str):
        with open(config_path) as f:
            self.config = yaml.safe_load(f)

        self.reasoning = ReasoningAgent(self.config)
        self.seed_gen = SeedGenerator(self.config)
        self.mutator_gen = MutatorGenerator(self.config)
        self.attention = AttentionComputer(self.config)
        self.afl = AFLRunner(self.config)
        self.scheduler = AttentionScheduler(self.config)

        self._running = True
        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)

    def _handle_signal(self, signum, frame):
        logger.info("Received signal %d, shutting down...", signum)
        self._running = False

    def run(self):
        logger.info("=== MA-HybridFuzz Starting ===")
        logger.info("Target: %s", self.config["target"]["binary"])
        logger.info("Target function: %s", self.config["target"]["target_function"])

        # Phase 1: Pre-phase (Gap 3 - LLM-based)
        logger.info("--- Phase 1: Pre-phase (LLM) ---")
        self._run_pre_phase()

        # Phase 2: Fuzzing loop (Gap 1 - Native speed)
        logger.info("--- Phase 2: Fuzzing Loop ---")
        self._run_fuzzing_loop()

        logger.info("=== MA-HybridFuzz Complete ===")
        self._report_results()

    def _run_pre_phase(self):
        # Step 1: Analyze target
        logger.info("[Pre-phase] Analyzing target...")
        analysis = self.reasoning.analyze_target(
            source_dir=self.config["target"]["source_dir"],
            target_function=self.config["target"]["target_function"],
            bug_type=self.config["target"]["bug_type"],
        )
        logger.info("[Pre-phase] Analysis complete: %d paths identified", len(analysis.get("paths", [])))

        # Step 2: Generate seeds
        logger.info("[Pre-phase] Generating reachable seeds...")
        seeds = self.seed_gen.generate(
            analysis=analysis,
            count=self.config["fuzzer"]["seed_count"],
        )
        logger.info("[Pre-phase] Generated %d seeds", len(seeds))

        # Step 3: Generate bug-specific mutators
        logger.info("[Pre-phase] Generating bug-specific mutators...")
        mutators = self.mutator_gen.generate(
            analysis=analysis,
            bug_type=self.config["target"]["bug_type"],
        )
        logger.info("[Pre-phase] Generated %d custom mutators", len(mutators))

        # Step 4: Compute attention distance matrix
        logger.info("[Pre-phase] Computing attention distance matrix...")
        self.attention.compute(
            source_dir=self.config["target"]["source_dir"],
            target_function=self.config["target"]["target_function"],
        )
        logger.info("[Pre-phase] Attention distance matrix cached")

    def _run_fuzzing_loop(self):
        # Instrument target binary
        logger.info("[Fuzzing] Instrumenting target binary...")
        instrumented = self.afl.instrument(
            binary=self.config["target"]["binary"],
            source_dir=self.config["target"]["source_dir"],
            use_asan=self.config["fuzzer"]["use_asan"],
        )

        # Load pre-computed data
        distance_matrix = self.attention.load_cached()
        self.scheduler.set_distance_matrix(distance_matrix)

        # Start AFL++ with custom scheduler and mutators
        logger.info("[Fuzzing] Starting AFL++ with attention-guided scheduling...")
        self.afl.start(
            instrumented_binary=instrumented,
            corpus_dir=self.config["paths"]["corpus"],
            crashes_dir=self.config["paths"]["crashes"],
            mutator_dir=self.config["paths"]["mutators"],
            scheduler=self.scheduler,
        )

        # Monitor loop
        timeout = self.config["fuzzer"]["timeout"]
        plateau_threshold = self.config["reassessment"]["plateau_threshold"]
        max_reassessments = self.config["reassessment"]["max_reassessments"]
        reassessment_count = 0
        last_new_coverage_time = time.time()
        last_coverage_count = 0
        start_time = time.time()

        while self._running and (time.time() - start_time) < timeout:
            time.sleep(10)
            stats = self.afl.get_stats()
            if stats is None:
                continue

            current_coverage = stats.get("paths_total", 0)
            crashes = stats.get("unique_crashes", 0)

            if current_coverage > last_coverage_count:
                last_coverage_count = current_coverage
                last_new_coverage_time = time.time()

            elapsed = time.time() - start_time
            logger.info(
                "[Fuzzing] %ds elapsed | coverage: %d | crashes: %d | execs: %s",
                int(elapsed),
                current_coverage,
                crashes,
                stats.get("execs_per_sec", "N/A"),
            )

            # Check for plateau -> trigger reassessment
            plateau_time = time.time() - last_new_coverage_time
            if (
                plateau_time > plateau_threshold
                and reassessment_count < max_reassessments
            ):
                logger.info(
                    "[Reassessment] Coverage plateau detected (%ds). Triggering LLM reassessment #%d...",
                    int(plateau_time),
                    reassessment_count + 1,
                )
                self._run_reassessment(stats)
                reassessment_count += 1
                last_new_coverage_time = time.time()

        self.afl.stop()

    def _run_reassessment(self, current_stats: dict):
        """On-demand LLM reassessment when fuzzer is stuck."""
        analysis = self.reasoning.reassess(
            current_stats=current_stats,
            coverage_dir=self.config["paths"]["coverage"],
            corpus_dir=self.config["paths"]["corpus"],
        )

        # Generate new seeds based on reassessment
        new_seeds = self.seed_gen.generate(
            analysis=analysis,
            count=self.config["fuzzer"]["seed_count"] // 2,
        )
        logger.info("[Reassessment] Generated %d new seeds", len(new_seeds))

        # Update mutators if needed
        new_mutators = self.mutator_gen.generate(
            analysis=analysis,
            bug_type=self.config["target"]["bug_type"],
        )
        logger.info("[Reassessment] Updated %d mutators", len(new_mutators))

    def _report_results(self):
        crashes_dir = Path(self.config["paths"]["crashes"])
        crash_files = list(crashes_dir.glob("id:*")) if crashes_dir.exists() else []
        logger.info("=== Results ===")
        logger.info("Total crashes found: %d", len(crash_files))
        logger.info("Crashes directory: %s", crashes_dir)
        logger.info("Logs: %s", self.config["paths"]["logs"])


def main():
    parser = argparse.ArgumentParser(description="MA-HybridFuzz Orchestrator")
    parser.add_argument(
        "-c", "--config",
        default="/opt/mahybridfuzz/configs/default.yml",
        help="Path to config file",
    )
    args = parser.parse_args()

    orchestrator = Orchestrator(args.config)
    orchestrator.run()


if __name__ == "__main__":
    main()
