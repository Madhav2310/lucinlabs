"""Session-level anomaly scoring — the correct alerting unit for behavioral.

MATURITY: L2 → exercised in benchmarks/behavioral_eval.py as a SMOKE TEST ONLY.
    The ~3.75% benign-session false-positive figure from that harness is CIRCULAR
    (benign traffic, conformal calibration, and the test set all come from the one
    synthetic generator in behavioral/trace_gen.py). It shows the session-level
    machinery runs and is internally consistent — it is NOT a validated real-world
    false-positive rate and must not be cited as detection evidence (Anti-Slop
    rules 2/3). It becomes a real number only on third-party traces we don't
    generate.

WHY THIS EXISTS (the hard lesson, measured 2026-07-29):
    Per-EVENT alerting cannot scale to sessions. Even at a per-event false-alarm
    rate α, a session of n events trips at least once with probability
    1-(1-α)^n — so α=4%, n=28 → ~96% benign SESSION false-alarm. Measured
    exactly that. The fix is not a threshold tweak; it is changing the unit of
    decision to the session.

THE DESIGN:
  1. Scan statistic: max over a small sliding window (default w=3) of the mean
     per-event score. This exploits the STRUCTURAL difference between attacks and
     benign noise: an attack is a CONTIGUOUS span of elevated events; benign
     false positives are SPORADIC and isolated. A lone benign spike is diluted by
     its window; a contiguous attack span is not.
  2. Per-role conformal threshold: the (1-α) quantile of the scan statistic over
     the role's BENIGN sessions (with +1 finite-sample smoothing). Flag a session
     iff its scan statistic exceeds the role threshold. This CONTROLS benign
     session false-alarm at ≈ α by construction (Mondrian, session-level).

HONEST LIMITS (do not fight these — fighting them reintroduces the 96% FP):
  - For roles that LEGITIMATELY do secret→egress (data-analyst reads DB creds then
    emails a report), a single-event exfil is behaviorally identical to benign; the
    conformal threshold absorbs it, so it is MISSED here. That case belongs to
    GUARD's content-taint / the IFC gate, not the content-blind behavioral layer.
  - Content-mimicry attacks (that imitate a benign role's tool distribution) carry
    ~0 behavioral signal and are not detectable at this layer.
  The behavioral layer's honest job: rate/volume/novelty anomalies and multi-event
  attacks. The layered defense (IFC + content-taint + behavioral) covers the rest.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field


def windowed_max_mean(event_scores: list[float], window: int) -> float:
    """Max over sliding windows of size `window` of the mean per-event score.

    window=1 → the single most-anomalous event (catches one decisive spike).
    window>=3 → a CONTIGUOUS span of elevated events (catches sustained attacks
    and suppresses a lone isolated benign spike, which gets diluted).
    """
    n = len(event_scores)
    if n == 0:
        return 0.0
    w = min(window, n)
    running = sum(event_scores[:w])
    best = running / w
    for i in range(w, n):
        running += event_scores[i] - event_scores[i - w]
        best = max(best, running / w)
    return best


def scan_statistic(event_scores: list[float], window: int = 3) -> float:
    """Back-compat single-window scan statistic (see windowed_max_mean)."""
    return windowed_max_mean(event_scores, window)


@dataclass
class SessionConformalThreshold:
    """Two-scale per-role conformal thresholds for session-level detection.

    Two anomaly shapes matter and a single window conflates them:
      - a SINGLE decisive event (w=1) — e.g. a Layer-0 secret→egress spike on a
        role that is normally quiet (support never reads secrets, so one such
        event is glaring). A w=3+ window dilutes it below threshold.
      - a SUSTAINED span (w=5) — harvest / volume attacks.
    We calibrate a SEPARATE per-role conformal threshold for each scale and flag
    a session if EITHER scale exceeds its threshold. To keep the union false-
    alarm rate ≤ alpha, each scale is calibrated at alpha/len(windows)
    (Bonferroni). A benign single spike raises only the w=1 threshold (not w=5),
    so it cannot mask a sustained attack, and vice-versa.

    calib_n must be >= len(windows)/alpha (e.g. 2/0.05 = 40) for a valid quantile
    at the per-scale level.
    """
    alpha: float = 0.05
    windows: tuple[int, ...] = (1, 5)
    _thr: dict[tuple, float] = field(default_factory=dict)   # (role, w) -> threshold

    def fit(self, benign_sessions_by_role: dict[str, list[list[float]]]) -> "SessionConformalThreshold":
        per_scale = self.alpha / len(self.windows)          # Bonferroni split
        for role, sessions in benign_sessions_by_role.items():
            for w in self.windows:
                stats = sorted(windowed_max_mean(es, w) for es in sessions if es)
                if not stats:
                    continue
                n = len(stats)
                idx = math.ceil((n + 1) * (1 - per_scale)) - 1
                idx = max(0, min(n - 1, idx))
                self._thr[(role, w)] = stats[idx]
        return self

    def flag(self, role: str, event_scores: list[float]) -> bool:
        for w in self.windows:
            thr = self._thr.get((role, w), float("inf"))
            if windowed_max_mean(event_scores, w) > thr:
                return True
        return False

    def which_scale(self, role: str, event_scores: list[float]) -> int | None:
        """Return the window scale that fired (for explainability), or None."""
        for w in self.windows:
            thr = self._thr.get((role, w), float("inf"))
            if windowed_max_mean(event_scores, w) > thr:
                return w
        return None
