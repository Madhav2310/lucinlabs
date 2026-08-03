"""Concept Drift Detection — detect when agent behavior legitimately changes.

Without drift detection, every agent update triggers a flood of alerts
because the "new normal" doesn't match the old baseline. This module:

1. Detects when the distribution of agent actions shifts significantly
2. Distinguishes between: attack (sudden, anomalous shift) vs. drift (gradual, legitimate change)
3. Automatically triggers baseline re-learning when drift is confirmed
4. Logs drift events for audit trail

Algorithm: Page-Hinkley test (sequential change detection)
- Monitors the cumulative deviation of anomaly scores from their mean
- Fires when cumulative deviation exceeds a threshold
- Low computational cost (O(1) per observation)
- Well-suited for online/streaming data

Reference: E.S. Page (1954), "Continuous Inspection Schemes"
Used by: River library, Frouros, MOA framework
"""

from dataclasses import dataclass
from datetime import datetime


@dataclass
class DriftEvent:
    """A detected drift event."""
    agent_id: str
    detected_at: datetime
    drift_magnitude: float
    observations_since_last_drift: int
    trigger: str  # "page_hinkley" | "window_comparison"
    recommendation: str  # "reset_baseline" | "investigate" | "ignore"


class PageHinkleyDetector:
    """Page-Hinkley test for sequential change detection.

    Monitors the running mean of anomaly scores and detects when
    the scores shift significantly from their historical average.

    A sudden increase in average anomaly score could mean:
    - An attack in progress (investigate immediately)
    - A legitimate behavior change (reset baseline)

    We distinguish by checking:
    - Speed of change (sudden = likely attack, gradual = likely drift)
    - Magnitude (extreme = attack, moderate = drift)
    - Reversibility (does it revert? = attack. Persists? = drift)
    """

    def __init__(
        self,
        delta: float = 0.01,       # Slack term — MUST be in the SAME UNITS as the
                                    # observed values (see note below).
        threshold: float = 15.0,    # Detection threshold (higher = fewer false alarms)
        burn_in: int = 30,          # Observations before detection activates
        recent_window: int = 10,    # Window used to summarise the *current* regime
    ):
        # NOTE ON `delta` SCALE (calibration footgun — learned the hard way):
        # The Page-Hinkley increment is (value - running_mean - delta). `delta` is
        # therefore in the SAME units as `value`. If you feed 0-100-scaled anomaly
        # scores, a delta of 0.01 is effectively zero, which turns the test into a
        # driftless random walk that flags a "drift" on almost any long stationary
        # stream (measured: >70% false-drift on stationary 0-100 streams). Set
        # delta to roughly the smallest sustained shift you care about, above the
        # per-observation noise. For 0-100 session-mean anomaly scores, delta≈5,
        # threshold≈20 gives 0% false-drift with a ~4-observation detection delay
        # (see benchmarks/drift_eval.py).
        self.delta = delta
        self.threshold = threshold
        self.burn_in = burn_in
        self.recent_window = recent_window

        # Internal state
        self._n: int = 0
        self._sum: float = 0.0
        self._mean: float = 0.0
        self._cumulative_sum: float = 0.0
        self._min_cumulative: float = float('inf')
        self._drift_detected: bool = False
        self._last_drift_at: int = 0
        self._recent: list[float] = []   # ring of the last `recent_window` values
        # Values observed SINCE the Page-Hinkley cumulative-sum last hit a new
        # minimum. That minimum is the change-point estimate, so these are the
        # post-change ("current regime") observations that actually drove the
        # alert — the right sample for classifying the shift regardless of how
        # fast it was detected.
        self._since_min: list[float] = []

    def update(self, value: float) -> bool:
        """Process a new observation (anomaly score).

        Args:
            value: The anomaly score (0-99) for the latest action

        Returns:
            True if drift is detected, False otherwise
        """
        self._n += 1
        self._sum += value
        self._mean = self._sum / self._n

        # Track the most-recent values so we can summarise the CURRENT regime
        # (not the lifetime average) when a drift is classified.
        self._recent.append(value)
        if len(self._recent) > self.recent_window:
            self._recent.pop(0)

        # Page-Hinkley statistic
        self._cumulative_sum += value - self._mean - self.delta
        if self._cumulative_sum < self._min_cumulative:
            # New minimum → change-point estimate moves to here. The value that
            # sets the min is the last pre-change point, so start the post-change
            # window empty.
            self._min_cumulative = self._cumulative_sum
            self._since_min = []
        else:
            self._since_min.append(value)
            # Bound memory in a long-running detector: the regime estimate only
            # needs the recent post-change tail, not the whole run.
            if len(self._since_min) > 1000:
                self._since_min.pop(0)

        # Drift condition: PH statistic exceeds threshold
        ph_value = self._cumulative_sum - self._min_cumulative

        if self._n > self.burn_in and ph_value > self.threshold:
            self._drift_detected = True
            self._last_drift_at = self._n
            return True

        return False

    def reset(self) -> None:
        """Reset the detector (call after baseline re-learning)."""
        self._n = 0
        self._sum = 0.0
        self._mean = 0.0
        self._cumulative_sum = 0.0
        self._min_cumulative = float('inf')
        self._drift_detected = False
        self._recent = []
        self._since_min = []

    @property
    def is_drifting(self) -> bool:
        """Whether drift has been detected since last reset."""
        return self._drift_detected

    @property
    def observations(self) -> int:
        """Number of observations processed."""
        return self._n

    @property
    def current_mean(self) -> float:
        """Lifetime running mean of anomaly scores (includes pre-drift history)."""
        return self._mean

    @property
    def recent_mean(self) -> float:
        """Mean of the last `recent_window` observations — i.e. the CURRENT regime.

        This is the right statistic for classifying a just-detected shift: the
        lifetime mean dilutes the new level with all the pre-drift history, so a
        late spike or a persistent moderate shift both look muted through it.
        """
        if not self._recent:
            return self._mean
        return sum(self._recent) / len(self._recent)

    @property
    def change_regime_mean(self) -> float:
        """Mean of observations since the Page-Hinkley change-point estimate.

        This is the level of the CURRENT (post-change) regime that triggered the
        alert. Unlike a fixed recent window, it is not diluted by pre-change
        history when the shift is detected quickly (e.g. a large sudden jump).
        Falls back to the recent-window mean when no post-change samples exist.
        """
        if self._since_min:
            return sum(self._since_min) / len(self._since_min)
        return self.recent_mean


class DriftMonitor:
    """Monitors multiple agents for concept drift.

    Wraps PageHinkleyDetector for each agent and provides
    high-level drift management (distinguish attack vs. drift,
    trigger baseline reset, log events).
    """

    def __init__(
        self,
        threshold: float = 15.0,
        burn_in: int = 30,
        delta: float = 0.01,
        recent_window: int = 10,
        investigate_level: float = 70.0,
    ):
        # `delta` is now forwarded to the per-agent detectors. Previously it was
        # NOT, so every detector silently used the driftless 0.01 default even on
        # 0-100 scores — the false-drift footgun documented in PageHinkleyDetector.
        self._detectors: dict[str, PageHinkleyDetector] = {}
        self._events: list[DriftEvent] = []
        self._threshold = threshold
        self._burn_in = burn_in
        self._delta = delta
        self._recent_window = recent_window
        # Anomaly-score level (0-99) above which a sustained shift is treated as a
        # likely attack campaign ("investigate") rather than a benign new normal
        # ("reset_baseline"). Tie this to your point-alert threshold: a sustained
        # regime whose *average* event is itself alert-worthy is not a new normal.
        self._investigate_level = investigate_level

    def observe(self, agent_id: str, anomaly_score: int) -> DriftEvent | None:
        """Observe an anomaly score and check for drift.

        Args:
            agent_id: The agent being monitored
            anomaly_score: The anomaly score (0-99) from the behavioral scorer

        Returns:
            DriftEvent if drift is detected, None otherwise
        """
        if agent_id not in self._detectors:
            self._detectors[agent_id] = PageHinkleyDetector(
                threshold=self._threshold,
                burn_in=self._burn_in,
                delta=self._delta,
                recent_window=self._recent_window,
            )

        detector = self._detectors[agent_id]
        drift_detected = detector.update(float(anomaly_score))

        if drift_detected:
            # Classify: is this an attack or a legitimate drift?
            event = self._classify_drift(agent_id, detector)
            self._events.append(event)
            return event

        return None

    def _classify_drift(self, agent_id: str, detector: PageHinkleyDetector) -> DriftEvent:
        """Classify whether detected drift is an attack or a legitimate change.

        Uses the RECENT-window mean (the current regime), NOT the lifetime mean.
        The lifetime mean averages in all the pre-drift history, so a benign
        moderate shift reads as low and a genuine sustained-attack campaign reads
        as low too — the very thing we need to tell apart. (Bug fixed: this used
        `current_mean`; on a stream that is benign for a long time then shifts,
        the lifetime mean stayed near the old baseline and mislabelled the shift.)

        Heuristic on the current regime's mean anomaly score (0-99):
        - >= investigate_level (default 70): the average event is itself
          alert-worthy → a sustained attack campaign → "investigate".
        - otherwise: a moderate, persistent new baseline → benign "new normal"
          → "reset_baseline" (re-learn so we stop alert-flooding).

        Note: a ONE-OFF attack is a transient spike that does not sustain the
        Page-Hinkley statistic, so it never reaches this classifier at all — it
        is handled by the point-anomaly layer. This method only ever sees
        *sustained* shifts.
        """
        recent_score = detector.change_regime_mean

        if recent_score >= self._investigate_level:
            recommendation = "investigate"  # sustained high-anomaly regime — likely attack
        else:
            recommendation = "reset_baseline"  # legitimate behavior change

        return DriftEvent(
            agent_id=agent_id,
            detected_at=datetime.now(),
            drift_magnitude=recent_score,
            observations_since_last_drift=detector.observations,
            trigger="page_hinkley",
            recommendation=recommendation,
        )

    def reset_agent(self, agent_id: str) -> None:
        """Reset drift detector for an agent (after baseline re-learning)."""
        if agent_id in self._detectors:
            self._detectors[agent_id].reset()

    @property
    def drift_events(self) -> list[DriftEvent]:
        """All detected drift events."""
        return self._events
