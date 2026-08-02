"""Score Calibration System — feedback loop for model improvement.

Allows security teams to mark scores as:
- FALSE POSITIVE: "This was flagged but is actually normal behavior"
- FALSE NEGATIVE: "This wasn't flagged but was actually an attack"
- CONFIRMED: "This alert was correct"

The feedback is used to:
1. Adjust scoring thresholds per agent
2. Add exceptions for known-safe patterns
3. Track precision/recall over time
4. Identify which models need retraining

This is the production quality feedback loop that makes the system
improve over time — not just with more data, but with LABELED data
from expert human reviewers.
"""

import json
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Literal


@dataclass
class FeedbackEntry:
    """A single feedback entry from a human reviewer."""
    timestamp: str
    agent_id: str
    tool_name: str
    original_score: int
    label: Literal["false_positive", "false_negative", "confirmed"]
    reviewer: str = ""
    notes: str = ""


@dataclass
class CalibrationState:
    """Current calibration state for the scoring system."""
    # Per-agent threshold adjustments
    threshold_adjustments: dict[str, int] = field(default_factory=dict)
    # Known-safe patterns (suppress alerts)
    safe_patterns: list[dict] = field(default_factory=list)
    # Accuracy tracking
    total_feedback: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    confirmed_alerts: int = 0

    @property
    def precision(self) -> float:
        """Precision = confirmed / (confirmed + false_positives)."""
        total_flagged = self.confirmed_alerts + self.false_positives
        if total_flagged == 0:
            return 1.0
        return self.confirmed_alerts / total_flagged

    @property
    def estimated_recall(self) -> float | None:
        """Estimated recall = confirmed / (confirmed + false_negatives).

        Returns None (UNKNOWN) when there is no labelled ground truth yet — with
        zero confirmed alerts and zero false negatives, recall is undefined, and
        reporting 1.0 ("perfect recall") from no data is a dangerous overclaim.
        """
        total_real = self.confirmed_alerts + self.false_negatives
        if total_real == 0:
            return None
        return self.confirmed_alerts / total_real


class ScoreCalibrator:
    """Manages score calibration based on human feedback.

    Usage:
        calibrator = ScoreCalibrator()
        calibrator.add_feedback("agent-1", "sql_query", score=72, label="false_positive")
        adjusted_score = calibrator.adjust_score("agent-1", "sql_query", raw_score=68)
    """

    def __init__(self, storage_path: Path | str = ".lucin/calibration.json"):
        self._storage_path = Path(storage_path)
        self._state = CalibrationState()
        self._feedback_log: list[FeedbackEntry] = []
        self._load()

    def add_feedback(
        self,
        agent_id: str,
        tool_name: str,
        score: int,
        label: Literal["false_positive", "false_negative", "confirmed"],
        reviewer: str = "",
        notes: str = "",
    ) -> None:
        """Record feedback on a scored action.

        This adjusts future scoring for this agent/tool combination.
        """
        entry = FeedbackEntry(
            timestamp=datetime.now().isoformat(),
            agent_id=agent_id,
            tool_name=tool_name,
            original_score=score,
            label=label,
            reviewer=reviewer,
            notes=notes,
        )
        self._feedback_log.append(entry)
        self._state.total_feedback += 1

        if label == "false_positive":
            self._state.false_positives += 1
            # Lower threshold for this agent (it's being over-flagged)
            current_adj = self._state.threshold_adjustments.get(agent_id, 0)
            self._state.threshold_adjustments[agent_id] = current_adj + 5  # Raise threshold by 5

            # Add as safe pattern if multiple FPs on same tool
            fp_count = sum(
                1 for f in self._feedback_log
                if f.agent_id == agent_id and f.tool_name == tool_name and f.label == "false_positive"
            )
            if fp_count >= 3:
                self._state.safe_patterns.append({
                    "agent_id": agent_id,
                    "tool_name": tool_name,
                    "added_at": datetime.now().isoformat(),
                    "reason": f"Marked FP {fp_count} times by reviewers",
                })

        elif label == "false_negative":
            self._state.false_negatives += 1
            # Lower threshold for this agent (it's being under-flagged)
            current_adj = self._state.threshold_adjustments.get(agent_id, 0)
            self._state.threshold_adjustments[agent_id] = current_adj - 5  # Lower threshold by 5

        elif label == "confirmed":
            self._state.confirmed_alerts += 1

        self._save()

    def adjust_score(self, agent_id: str, tool_name: str, raw_score: int) -> int:
        """Adjust a raw anomaly score based on calibration feedback.

        Returns the calibrated score (may be higher or lower than raw).
        """
        # Check if this is a known-safe pattern (suppress entirely)
        for pattern in self._state.safe_patterns:
            if pattern["agent_id"] == agent_id and pattern["tool_name"] == tool_name:
                return 0  # Suppress — confirmed safe by reviewers

        # Apply threshold adjustment
        adjustment = self._state.threshold_adjustments.get(agent_id, 0)
        calibrated = max(0, min(99, raw_score - adjustment))

        return calibrated

    def get_metrics(self) -> dict:
        """Get calibration metrics for monitoring."""
        return {
            "total_feedback": self._state.total_feedback,
            "false_positives": self._state.false_positives,
            "false_negatives": self._state.false_negatives,
            "confirmed_alerts": self._state.confirmed_alerts,
            "precision": round(self._state.precision, 3),
            # None when undefined (no labelled ground truth) — reported as-is so
            # callers see "unknown", never a fabricated 1.0.
            "estimated_recall": (round(er, 3)
                                 if (er := self._state.estimated_recall) is not None
                                 else None),
            "agents_adjusted": len(self._state.threshold_adjustments),
            "safe_patterns": len(self._state.safe_patterns),
        }

    def _save(self) -> None:
        """Persist calibration state to disk."""
        self._storage_path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "state": {
                "threshold_adjustments": self._state.threshold_adjustments,
                "safe_patterns": self._state.safe_patterns,
                "total_feedback": self._state.total_feedback,
                "false_positives": self._state.false_positives,
                "false_negatives": self._state.false_negatives,
                "confirmed_alerts": self._state.confirmed_alerts,
            },
            "feedback_log": [
                {
                    "timestamp": f.timestamp,
                    "agent_id": f.agent_id,
                    "tool_name": f.tool_name,
                    "original_score": f.original_score,
                    "label": f.label,
                    "reviewer": f.reviewer,
                    "notes": f.notes,
                }
                for f in self._feedback_log[-100:]  # Keep last 100 entries
            ],
        }
        self._storage_path.write_text(json.dumps(data, indent=2))

    def _load(self) -> None:
        """Load calibration state from disk."""
        if not self._storage_path.exists():
            return
        try:
            data = json.loads(self._storage_path.read_text())
            state_data = data.get("state", {})
            self._state.threshold_adjustments = state_data.get("threshold_adjustments", {})
            self._state.safe_patterns = state_data.get("safe_patterns", [])
            self._state.total_feedback = state_data.get("total_feedback", 0)
            self._state.false_positives = state_data.get("false_positives", 0)
            self._state.false_negatives = state_data.get("false_negatives", 0)
            self._state.confirmed_alerts = state_data.get("confirmed_alerts", 0)
        except (json.JSONDecodeError, KeyError):
            pass
