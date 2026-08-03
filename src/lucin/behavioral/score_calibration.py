"""Statistical score calibration for the behavioral detector.

MATURITY: L2 → validated in tests + benchmarks/behavioral_eval.py on synthetic labels.

Blueprint §6.2: "isotonic (raw GBDT/ensemble scores aren't probabilities) +
Mondrian/class-conditional conformal (standard conformal collapses to ~52.9%
coverage under 1:345 imbalance)."

Two complementary tools:

  IsotonicCalibrator — maps raw anomaly scores → calibrated probabilities via
    monotonic regression. Reports Brier score improvement. Answers "when the
    detector says 0.8, how often is it actually an attack?"

  MondrianConformal — class-/group-conditional conformal p-values. For each
    group (e.g. agent role) it calibrates a nonconformity threshold from that
    group's benign scores, so the false-alarm rate is controlled PER GROUP even
    under heavy class imbalance. Answers "flag at most alpha fraction of benign
    events in each role."

Distinct from calibration.py (that is a human-feedback threshold-adjuster; this
is statistical probability/coverage calibration).
"""

from __future__ import annotations

from dataclasses import dataclass, field


def brier_score(probs: list[float], labels: list[int]) -> float:
    """Mean squared error between predicted probabilities and 0/1 labels."""
    if not probs:
        return 0.0
    return sum((p - y) ** 2 for p, y in zip(probs, labels)) / len(probs)


class IsotonicCalibrator:
    """Monotonic calibration of raw scores → probabilities (sklearn-backed)."""

    def __init__(self):
        self._iso = None
        self._fitted = False

    def fit(self, scores: list[float], labels: list[int]) -> "IsotonicCalibrator":
        from sklearn.isotonic import IsotonicRegression
        self._iso = IsotonicRegression(out_of_bounds="clip", y_min=0.0, y_max=1.0)
        self._iso.fit(scores, labels)
        self._fitted = True
        return self

    def predict(self, scores: list[float]) -> list[float]:
        if not self._fitted:
            raise RuntimeError("IsotonicCalibrator.fit() must be called first")
        return [float(p) for p in self._iso.predict(scores)]

    def brier_improvement(self, scores: list[float], labels: list[int]) -> dict:
        """Brier score raw (scores as-is) vs calibrated. Lower is better."""
        raw = brier_score([min(1.0, max(0.0, s)) for s in scores], labels)
        cal = brier_score(self.predict(scores), labels)
        return {"brier_raw": round(raw, 4), "brier_calibrated": round(cal, 4),
                "improvement": round(raw - cal, 4)}


@dataclass
class MondrianConformal:
    """Group-conditional (Mondrian) conformal calibration for anomaly scores.

    Higher score = more anomalous. For each group we store the benign
    calibration scores; the conformal p-value of a new point is the fraction of
    benign calibration scores >= the point's score (with the standard +1
    smoothing). p <= alpha ⇒ flag. Per-group calibration keeps the benign
    false-alarm rate ≈ alpha within EACH group, which plain conformal loses
    under class imbalance.
    """
    alpha: float = 0.05                              # target per-group benign FP rate
    _cal: dict[str, list[float]] = field(default_factory=dict)

    def fit(self, benign_scores_by_group: dict[str, list[float]]) -> "MondrianConformal":
        self._cal = {g: sorted(s) for g, s in benign_scores_by_group.items() if s}
        return self

    def p_value(self, group: str, score: float) -> float:
        cal = self._cal.get(group)
        if not cal:
            return 1.0                                # no calibration → never flag
        n = len(cal)
        n_ge = sum(1 for s in cal if s >= score)
        return (1 + n_ge) / (n + 1)

    def is_anomalous(self, group: str, score: float) -> bool:
        return self.p_value(group, score) <= self.alpha

    def group_false_alarm_rates(self,
                                benign_scores_by_group: dict[str, list[float]]) -> dict:
        """Measured benign flag rate per group on a held-out benign set.

        Should be ≈ alpha if the coverage guarantee holds.
        """
        out = {}
        for g, scores in benign_scores_by_group.items():
            if not scores:
                continue
            flagged = sum(1 for s in scores if self.is_anomalous(g, s))
            out[g] = round(flagged / len(scores), 4)
        return out
