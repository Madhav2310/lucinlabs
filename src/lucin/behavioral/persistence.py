"""Behavioral Model Persistence — save and load learned baselines.

Without this, the behavioral monitor loses all learned baselines when
the process restarts. That means 60-90 days of baseline learning is
lost on every restart — unacceptable for production.

This module provides:
1. Save baseline state to disk (JSON serialization)
2. Load baseline state from disk (restore after restart)
3. Periodic auto-save (every N actions or every M minutes)
4. Baseline versioning (track when baselines were last updated)
5. Export/import for migration between environments

Architecture decision: We use JSON (not pickle) because:
- JSON is human-readable (auditable)
- JSON is safe (no arbitrary code execution on load)
- JSON is portable (move between Python versions)
- The performance hit is negligible (baselines are small)
"""

import json
import time
from datetime import datetime
from pathlib import Path

from lucin.behavioral.scoring import AgentBaseline, BehavioralScorer


class BaselinePersistence:
    """Manages saving and loading of behavioral baselines."""

    def __init__(self, storage_dir: Path | str = ".lucin/baselines"):
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self._last_save_time = time.time()
        self._actions_since_save = 0

    def save(self, scorer: BehavioralScorer, reason: str = "manual") -> Path:
        """Save the current scorer state to disk.

        Returns the path to the saved file.
        """
        state = self._serialize_scorer(scorer)
        state["metadata"] = {
            "saved_at": datetime.now().isoformat(),
            "reason": reason,
            "total_observations": scorer._global_stats.total_observations,
            "agents_baselined": scorer.baseline_count,
            "version": "1.0",
        }

        filename = f"baselines_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = self.storage_dir / filename

        filepath.write_text(json.dumps(state, indent=2, default=str))

        # Also save as "latest" for easy loading
        latest_path = self.storage_dir / "latest.json"
        latest_path.write_text(json.dumps(state, indent=2, default=str))

        self._last_save_time = time.time()
        self._actions_since_save = 0

        return filepath

    def load(self, scorer: BehavioralScorer, filepath: Path | str | None = None) -> dict:
        """Load a previously saved baseline into the scorer.

        Args:
            scorer: The BehavioralScorer to restore state into
            filepath: Specific file to load (default: load latest)

        Returns:
            Metadata dict about the loaded baseline
        """
        if filepath is None:
            filepath = self.storage_dir / "latest.json"

        filepath = Path(filepath)
        if not filepath.exists():
            return {"error": "No saved baseline found", "path": str(filepath)}

        state = json.loads(filepath.read_text())
        self._deserialize_into_scorer(scorer, state)

        return state.get("metadata", {})

    def should_auto_save(self, actions_threshold: int = 100, time_threshold_minutes: int = 5) -> bool:
        """Check if an auto-save is due based on actions or time."""
        self._actions_since_save += 1

        if self._actions_since_save >= actions_threshold:
            return True

        elapsed_minutes = (time.time() - self._last_save_time) / 60
        if elapsed_minutes >= time_threshold_minutes:
            return True

        return False

    def list_saved_baselines(self) -> list[dict]:
        """List all saved baseline files with metadata."""
        baselines = []
        for f in sorted(self.storage_dir.glob("baselines_*.json")):
            try:
                data = json.loads(f.read_text())
                meta = data.get("metadata", {})
                meta["file"] = str(f)
                meta["size_bytes"] = f.stat().st_size
                baselines.append(meta)
            except (json.JSONDecodeError, OSError):
                continue
        return baselines

    def _serialize_scorer(self, scorer: BehavioralScorer) -> dict:
        """Convert scorer state to a JSON-serializable dict."""
        baselines = {}
        for agent_id, baseline in scorer._baselines.items():
            baselines[agent_id] = {
                "observation_count": baseline.observation_count,
                "avg_actions_per_minute": baseline.avg_actions_per_minute,
                "avg_param_length": baseline.avg_param_length,
                "avg_param_entropy": baseline.avg_param_entropy,
                "hour_distribution": baseline.hour_distribution,
                "tool_frequencies": baseline.tool_frequencies,
                "usually_accesses_sensitive": baseline.usually_accesses_sensitive,
                # Sequence memory — persist so the learned transition graph is
                # not lost on restart (previously dropped silently).
                "last_tools": baseline.last_tools,
                "transition_counts": baseline.transition_counts,
                "_tool_counts": baseline._tool_counts,
            }

        return {
            "baselines": baselines,
            "global_stats": {
                "total_observations": scorer._global_stats.total_observations,
                "tool_usage_rates": scorer._global_stats.tool_usage_rates,
            },
        }

    def _deserialize_into_scorer(self, scorer: BehavioralScorer, state: dict) -> None:
        """Restore scorer state from a serialized dict."""
        # Restore baselines
        for agent_id, baseline_data in state.get("baselines", {}).items():
            baseline = AgentBaseline(agent_id=agent_id)
            baseline.observation_count = baseline_data.get("observation_count", 0)
            baseline.avg_actions_per_minute = baseline_data.get("avg_actions_per_minute", 0.0)
            baseline.avg_param_length = baseline_data.get("avg_param_length", 100.0)
            baseline.avg_param_entropy = baseline_data.get("avg_param_entropy", 3.0)
            baseline.hour_distribution = {
                int(k): v for k, v in baseline_data.get("hour_distribution", {}).items()
            }
            baseline.tool_frequencies = baseline_data.get("tool_frequencies", {})
            baseline.usually_accesses_sensitive = baseline_data.get("usually_accesses_sensitive", False)
            # Restore sequence memory (transition graph) — keys stay strings.
            baseline.last_tools = baseline_data.get("last_tools", [])
            baseline.transition_counts = baseline_data.get("transition_counts", {})
            baseline._tool_counts = baseline_data.get("_tool_counts", {})
            scorer._baselines[agent_id] = baseline

        # Restore global stats
        global_data = state.get("global_stats", {})
        scorer._global_stats.total_observations = global_data.get("total_observations", 0)
        scorer._global_stats.tool_usage_rates = global_data.get("tool_usage_rates", {})
