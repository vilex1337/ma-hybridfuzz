"""
Persistent Memory - MA-HybridFuzz on-disk state store.

Project.md requirement:
  "Persistent Memory: Lưu attention map + confidence history + executed paths
   → tránh drift mà không cần gọi LLM thường xuyên."
  (Store attention map + confidence history + executed paths
   → avoid drift without frequent LLM calls.)

Three responsibilities:

1. Pre-phase context cache
   Saves bug_info, target_summary, program_usage after the pre-phase so that
   a restarted orchestrator can reload them without calling the LLM again.
   The cache is keyed by (target_function, bug_type) so different targets
   get independent memory.

2. Reassessment history
   Records every reassessment: when it fired, the diagnosis, what seeds were
   produced, and whether coverage improved afterward. This is passed back to
   ReassessmentAgent so it avoids repeating failed strategies.

3. Coverage / confidence snapshots
   Periodic snapshots of AFL++ stats let the orchestrator measure whether a
   reassessment actually helped (confidence), and provide the LLM with a
   richer picture of execution history beyond the last stats poll.

All state is stored as JSON in the configured memory directory so it is
human-readable, survives process restarts, and can be inspected for debugging.
"""

import json
import logging
import time
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("pre_phase.memory")

# File names inside the memory directory
_PRE_PHASE_FILE = "pre_phase_ctx.json"
_REASSESSMENT_FILE = "reassessment_history.json"
_COVERAGE_FILE = "coverage_snapshots.json"
_META_FILE = "memory_meta.json"


class PersistentMemory:
    """
    On-disk persistent memory for MA-HybridFuzz.

    Usage pattern in orchestrator:
        mem = PersistentMemory(config)
        # Pre-phase: load or compute
        ctx = mem.load_pre_phase_ctx(target_function, bug_type)
        if ctx is None:
            ctx = <run LLM pre-phase>
            mem.save_pre_phase_ctx(target_function, bug_type, ctx)
        # Fuzzing loop: snapshot coverage
        mem.record_coverage_snapshot(afl_stats)
        # Reassessment: record + retrieve history
        history = mem.get_reassessment_history()
        mem.record_reassessment(count, diagnosis, plan, seeds_written, coverage_before)
        # After fuzzing resumes: update confidence
        mem.update_reassessment_confidence(count, coverage_after)
    """

    def __init__(self, config: dict):
        self._dir = Path(config["paths"].get("memory", "/workspace/memory"))
        self._dir.mkdir(parents=True, exist_ok=True)
        self._ensure_meta()

    # -------------------------------------------------------------------------
    # 1. Pre-phase context cache
    # -------------------------------------------------------------------------

    def save_pre_phase_ctx(
        self, target_function: str, bug_type: str, ctx: dict[str, Any]
    ) -> None:
        """
        Persist the pre-phase LLM results to disk.

        Saves bug_info, target_summary, program_usage, and input_format so
        that a restarted orchestrator can skip the LLM pre-phase entirely.
        """
        payload = {
            "target_function": target_function,
            "bug_type": bug_type,
            "saved_at": time.time(),
            "ctx": ctx,
        }
        path = self._dir / _PRE_PHASE_FILE
        path.write_text(json.dumps(payload, indent=2))
        logger.info("[Memory] Pre-phase context saved → %s", path)

    def load_pre_phase_ctx(
        self, target_function: str, bug_type: str
    ) -> Optional[dict[str, Any]]:
        """
        Load a previously saved pre-phase context if it matches the current target.

        Returns None when no cache exists or the cache is for a different target,
        signalling the orchestrator to run the full pre-phase.
        """
        path = self._dir / _PRE_PHASE_FILE
        if not path.exists():
            return None
        try:
            payload = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("[Memory] Could not load pre-phase cache: %s", e)
            return None

        if (
            payload.get("target_function") != target_function
            or payload.get("bug_type") != bug_type
        ):
            logger.info(
                "[Memory] Pre-phase cache is for a different target (%s / %s), ignoring.",
                payload.get("target_function"),
                payload.get("bug_type"),
            )
            return None

        age_h = (time.time() - payload.get("saved_at", 0)) / 3600
        logger.info(
            "[Memory] Loaded pre-phase context (target=%s, age=%.1fh) — skipping LLM pre-phase.",
            target_function,
            age_h,
        )
        return payload["ctx"]

    def invalidate_pre_phase_ctx(self) -> None:
        """Delete the pre-phase cache (e.g. when config changes)."""
        path = self._dir / _PRE_PHASE_FILE
        if path.exists():
            path.unlink()
            logger.info("[Memory] Pre-phase context cache invalidated.")

    # -------------------------------------------------------------------------
    # 2. Reassessment history
    # -------------------------------------------------------------------------

    def record_reassessment(
        self,
        count: int,
        diagnosis: dict[str, Any],
        plan: dict[str, Any],
        seeds_written: int,
        coverage_before: int,
    ) -> None:
        """
        Record a reassessment event immediately after it fires.

        confidence_delta is filled in later by update_reassessment_confidence()
        once the fuzzer has had time to act on the new seeds/mutators.
        """
        history = self._load_json(_REASSESSMENT_FILE, default=[])
        if not isinstance(history, list):
            logger.warning("[Memory] Corrupt data in %s, resetting.", _REASSESSMENT_FILE)
            history = []
        entry: dict[str, Any] = {
            "id": count,
            "timestamp": time.time(),
            "stuck_type": diagnosis.get("stuck_type", "unknown"),
            "cause": diagnosis.get("cause", ""),
            "hypothesis": diagnosis.get("hypothesis", ""),
            "priority_gaps": diagnosis.get("priority_gaps", []),
            "diagnosis_confidence": diagnosis.get("confidence", 0.0),
            "rationale": plan.get("rationale", ""),
            "mutator_focus": plan.get("mutator_focus", ""),
            "seeds_written": seeds_written,
            "coverage_before": coverage_before,
            "coverage_after": None,       # filled by update_reassessment_confidence
            "confidence_delta": None,     # filled by update_reassessment_confidence
        }
        history.append(entry)
        self._save_json(_REASSESSMENT_FILE, history)
        logger.info(
            "[Memory] Reassessment #%d recorded (stuck_type=%s, seeds=%d).",
            count,
            entry["stuck_type"],
            seeds_written,
        )

    def update_reassessment_confidence(
        self, count: int, coverage_after: int
    ) -> None:
        """
        Update the confidence delta for a reassessment after the fuzzer has
        had time to act on the generated seeds and mutators.

        confidence_delta = coverage_after - coverage_before (positive = helped).
        """
        history = self._load_json(_REASSESSMENT_FILE, default=[])
        if not isinstance(history, list):
            logger.warning("[Memory] Corrupt data in %s, resetting.", _REASSESSMENT_FILE)
            return
        for entry in history:
            if entry.get("id") == count:
                before = entry.get("coverage_before", 0) or 0
                entry["coverage_after"] = coverage_after
                entry["confidence_delta"] = coverage_after - before
                break
        self._save_json(_REASSESSMENT_FILE, history)

    def get_reassessment_history(self) -> list[dict[str, Any]]:
        """Return all recorded reassessment entries, oldest first."""
        result = self._load_json(_REASSESSMENT_FILE, default=[])
        if not isinstance(result, list):
            logger.warning("[Memory] Corrupt data in %s, resetting.", _REASSESSMENT_FILE)
            return []
        return result

    def get_failed_strategies(self) -> list[str]:
        """
        Return a list of stuck_type / strategy descriptions that previously
        did not improve coverage (confidence_delta <= 0).

        Passed to ReassessmentAgent so it avoids repeating them.
        """
        history = self.get_reassessment_history()
        failed = []
        for entry in history:
            delta = entry.get("confidence_delta")
            if delta is not None and delta <= 0:
                desc = (
                    f"[#{entry['id']}] {entry.get('stuck_type','?')}: "
                    f"{entry.get('hypothesis', '')[:100]}"
                )
                failed.append(desc)
        return failed

    # -------------------------------------------------------------------------
    # 3. Coverage / confidence snapshots
    # -------------------------------------------------------------------------

    def record_coverage_snapshot(self, afl_stats: dict[str, Any]) -> None:
        """
        Record a lightweight AFL++ coverage snapshot.

        Called periodically from the fuzzing loop monitor. Snapshots give the
        reassessment agent a richer picture of execution history (trends, not
        just the latest poll).
        """
        snapshots = self._load_json(_COVERAGE_FILE, default=[])
        if not isinstance(snapshots, list):
            logger.warning("[Memory] Corrupt data in %s, resetting.", _COVERAGE_FILE)
            snapshots = []
        snapshots.append({
            "timestamp": time.time(),
            "paths_total": afl_stats.get("paths_total", 0),
            "unique_crashes": afl_stats.get("unique_crashes", 0),
            "execs_done": afl_stats.get("execs_done", 0),
            "execs_per_sec": afl_stats.get("execs_per_sec", "?"),
            "bitmap_cvg": afl_stats.get("bitmap_cvg", "?"),
        })
        # Keep only the last 500 snapshots to bound disk usage
        if len(snapshots) > 500:
            snapshots = snapshots[-500:]
        self._save_json(_COVERAGE_FILE, snapshots)

    def get_coverage_trend(self, last_n: int = 10) -> list[dict[str, Any]]:
        """Return the most recent N coverage snapshots for trend analysis."""
        snapshots = self._load_json(_COVERAGE_FILE, default=[])
        if not isinstance(snapshots, list):
            logger.warning("[Memory] Corrupt data in %s, resetting.", _COVERAGE_FILE)
            return []
        return snapshots[-last_n:]

    def get_coverage_at(self, timestamp: float) -> Optional[int]:
        """Return the paths_total closest to the given timestamp."""
        snapshots = self._load_json(_COVERAGE_FILE, default=[])
        if not isinstance(snapshots, list):
            logger.warning("[Memory] Corrupt data in %s, resetting.", _COVERAGE_FILE)
            return None
        if not snapshots:
            return None
        closest = min(snapshots, key=lambda s: abs(s.get("timestamp", 0) - timestamp))
        return closest.get("paths_total")

    # -------------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------------

    def summary(self) -> dict[str, Any]:
        """Return a human-readable summary of memory state."""
        history = self.get_reassessment_history()
        snapshots = self._load_json(_COVERAGE_FILE, default=[])
        if not isinstance(snapshots, list):
            snapshots = []
        pre_phase_path = self._dir / _PRE_PHASE_FILE
        return {
            "memory_dir": str(self._dir),
            "pre_phase_cached": pre_phase_path.exists(),
            "reassessment_count": len(history),
            "failed_strategies": len(self.get_failed_strategies()),
            "coverage_snapshots": len(snapshots),
            "latest_coverage": snapshots[-1].get("paths_total") if snapshots else None,
        }

    def _ensure_meta(self) -> None:
        """Write or update a human-readable metadata file in the memory dir."""
        meta_path = self._dir / _META_FILE
        meta = {
            "description": "MA-HybridFuzz persistent memory store",
            "files": {
                _PRE_PHASE_FILE: "Cached pre-phase LLM context (bug_info, target_summary, program_usage)",
                _REASSESSMENT_FILE: "History of on-demand reassessment events with confidence deltas",
                _COVERAGE_FILE: "Periodic AFL++ coverage snapshots for trend analysis",
            },
        }
        try:
            meta_path.write_text(json.dumps(meta, indent=2))
        except OSError:
            pass

    def _load_json(self, filename: str, default: Any) -> Any:
        path = self._dir / filename
        if not path.exists():
            return default
        try:
            return json.loads(path.read_text())
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("[Memory] Could not read %s: %s", filename, e)
            return default

    def _save_json(self, filename: str, data: Any) -> None:
        path = self._dir / filename
        try:
            path.write_text(json.dumps(data, indent=2))
        except OSError as e:
            logger.error("[Memory] Could not write %s: %s", filename, e)
