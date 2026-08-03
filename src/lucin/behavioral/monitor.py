"""AgentMonitor — connects event templating, feature engineering, and ML scoring.

Blueprint §6.2: near-inline behavioral scoring (the blueprint's "sub-ms" is
corrected to MEASURED ~5 ms/event at 10 trees) over "the craft that is the
actual edge" (ICSE 2022 arXiv:2202.04301, F1 swings 0.73→0.10 from the parser).

This module wires together:
  TrajectoryFeaturizer  → EventFeatureVector (the parser + fraud-style features)
  RollingNormalizer     → [0,1]-normalized feature vector
  StreamingEnsemble     → AnomalyScore (HST + LODA, prequential, ~5 ms/event)

One AgentMonitor per agent-role. Create a MonitorSession per agent execution.

Usage:
    monitor = AgentMonitor(role="customer-support-agent")
    session = monitor.new_session("session-abc-123")

    # On each tool call:
    result = session.observe("read_database", args={"query": "..."}, timestamp=t)
    if result.alert:
        log_alert(result)

    # After a warmup period, get the role baseline:
    monitor.update_role_prior(session)
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass

from lucin.behavioral.drift import DriftEvent, DriftMonitor
from lucin.behavioral.streaming import AnomalyScore, RollingNormalizer, StreamingEnsemble
from lucin.behavioral.trajectory import (
    EventFeatureVector,
    TrajectoryFeaturizer,
)

FEATURE_DIM = 6  # matches EventFeatureVector.to_vector()
FEATURE_NAMES = [
    "egress_ratio",
    "secret_read_velocity",
    "total_velocity",
    "transition_surprisal",
    "is_sensitive_tool",
    "role_egress_ratio_z",
]

# Warmup: the detector is in "learning" mode for this many events
# before it starts issuing alerts. This suppresses cold-start FPs.
DEFAULT_WARMUP_EVENTS = 30

# Layer-0 deterministic rule: tool-name substrings that indicate outbound egress
# (data leaving the trust boundary). Blueprint §6.2 Layer-0.
_EGRESS_TOOL_MARKERS = (
    "post", "send", "upload", "webhook", "email", "notify",
    "write", "put", "patch", "publish", "export", "transmit",
)


# Layer-0 toxic-transition: what counts as a SECRET read. Deliberately NARROW —
# `read_file`/`query_db` are common benign operations and must NOT trip the
# secret→egress rule (that conflation caused ~22% benign false positives).
# A toxic transition is credential/key/secret/token read → egress, nothing looser.
_SECRET_READ_MARKERS = (
    "read_secret", "get_secret", "fetch_secret", "read_cred", "get_cred",
    "read_key", "fetch_key", "get_key", "read_token", "get_token",
    "read_env", "get_env", "read_password", "get_password",
    "vault", "secrets_manager", "credential", "api_key",
)
# How many events a secret read stays "recent" for the toxic-transition rule.
_SECRET_RECENCY_WINDOW = 10


def _is_secret_read(tool_name: str) -> bool:
    low = tool_name.lower()
    return any(m in low for m in _SECRET_READ_MARKERS)


# Role-deviation signal parameters.
_ROLE_DEV_MIN_EVENTS = 20     # need enough events for a stable proportion estimate
_ROLE_DEV_ABS_FLOOR  = 0.30   # session egress fraction must be genuinely elevated
_ROLE_DEV_MARGIN     = 0.05   # session rate must clear role rate by this margin


def _wilson_lower_bound(k: int, n: int, z: float = 1.96) -> float:
    """One-sided Wilson score lower bound for a binomial proportion.

    The statistically correct way to ask "is the session's egress RATE
    confidently above the role's, given n observations?" Small n → wide interval
    → low bound → no premature firing on an opening burst. As sustained evidence
    accumulates, the bound rises. A transient burst in a long session barely
    moves the cumulative proportion, so the bound stays put. This is what
    separates 'role-abnormal sustained egress' from 'benign burst' structurally,
    rather than by a hand-tuned threshold.
    """
    if n <= 0:
        return 0.0
    phat = k / n
    z2 = z * z
    denom = 1.0 + z2 / n
    centre = phat + z2 / (2 * n)
    margin = z * math.sqrt((phat * (1 - phat) + z2 / (4 * n)) / n)
    return max(0.0, (centre - margin) / denom)


def _is_egress_event(tool_name: str, event_key: str) -> bool:
    """True if this event sends data outward to an external destination.

    Runtime analogue of the static egress classification: an egress-type tool
    name AND an external target class. web_search:external is a FETCH (data in),
    not egress, so we gate on the egress tool markers, not just ':external'.
    """
    if not event_key.endswith(":external"):
        return False
    low = tool_name.lower()
    return any(m in low for m in _EGRESS_TOOL_MARKERS)


@dataclass
class MonitorEvent:
    """One observed tool call with its anomaly score."""
    tool_name:    str
    args:         dict
    timestamp:    float
    features:     EventFeatureVector
    score:        AnomalyScore

    @property
    def alert(self) -> bool:
        return self.score.is_anomalous

    @property
    def top_contributing_features(self) -> list[tuple[str, float]]:
        """Return features sorted by anomaly contribution (highest first)."""
        contribs = self.score.feature_contributions
        return sorted(contribs.items(), key=lambda x: -x[1])[:3]

    def describe(self) -> str:
        lines = [
            f"{'ALERT' if self.alert else 'OK'}  tool={self.tool_name!r}  "
            f"score={self.score.score:.3f} (threshold={self.score.threshold:.2f})"
        ]
        if self.alert:
            lines.append(f"  event_key: {self.features.event_key}")
            lines.append(f"  surprisal: {self.features.transition_surprisal:.2f}  "
                         f"egress_ratio: {self.features.egress_ratio:.2f}  "
                         f"secret_velocity: {self.features.secret_read_velocity:.2f}")
            top = self.top_contributing_features
            if top:
                lines.append("  top drivers: " + ", ".join(
                    f"{name}={v:.3f}" for name, v in top))
        return "\n".join(lines)


class MonitorSession:
    """One agent execution (one conversation / one task).

    Each session has its own featurizer and detector instance so sessions
    don't contaminate each other's baselines. The parent AgentMonitor
    aggregates across sessions to update the role prior.
    """

    def __init__(self,
                 session_id: str,
                 role: str,
                 role_prior: dict[str, tuple[float, float]] | None,
                 threshold: float,
                 warmup_events: int,
                 hst_window: int = 100,
                 role_deviation: bool = True,
                 role_egress_rate: float | None = None):
        self.session_id   = session_id
        self.role         = role
        self.warmup_events = warmup_events
        # Role-relative deviation signal (the per-role-baseline network effect).
        # Now a self-calibrating one-sided Wilson proportion test against the
        # role's LEARNED egress rate — not tuned thresholds. Validated on
        # synthetic scenarios: catches role-abnormal sustained egress (TP) while
        # giving 0 FP on benign role-normal traffic AND benign bursts (the case
        # a per-event threshold could not separate). Safe-by-construction: with
        # no learned baseline (role_egress_rate is None) it never fires, so a
        # cold monitor cannot false-positive. ON by default. Real-world
        # calibration comes free — p_role is the customer's own benign rate.
        self.role_deviation = role_deviation
        self._featurizer  = TrajectoryFeaturizer(role_prior=role_prior)
        self._normalizer  = RollingNormalizer(dim=FEATURE_DIM)
        # hst_window sets the HST reference-window length. It must be <= the
        # expected session length or the HST stays in warmup and contributes 0.
        self._detector    = StreamingEnsemble(
            dim=FEATURE_DIM,
            feature_names=FEATURE_NAMES,
            threshold=threshold,
            window=hst_window,
        )
        self.events:     list[MonitorEvent] = []
        self.alerts:     list[MonitorEvent] = []
        # Set True if the role-deviation (Wilson) signal ever judged THIS session's
        # egress rate confidently role-abnormal. Used by AgentMonitor.learn_from to
        # refuse to fold such a session's egress rate back into the role baseline
        # (self-poisoning prevention — see learn_from).
        self._role_deviation_fired = False
        self._warmed_up  = False
        self._last_secret_read_at = -(10 ** 9)   # event index of last true-secret read
        # Role-deviation state: cumulative external/total counts + the role's
        # known egress rate (from the prior). The Wilson test compares them.
        self._cum_total    = 0
        self._cum_external = 0
        # The role's egress rate MUST be measured on the same statistic the
        # Wilson test uses — the true cumulative external/total fraction — NOT
        # the featurizer's decayed egress_ratio (mismatched half-lives bias it
        # high, which silently suppressed genuine detections). Supplied by the
        # AgentMonitor from prior sessions' true fractions.
        self._role_egress_rate = role_egress_rate

    @property
    def egress_fraction(self) -> float:
        """True cumulative external/total fraction for this session."""
        return self._cum_external / self._cum_total if self._cum_total else 0.0

    def observe(self,
                tool_name: str,
                args: dict | None = None,
                timestamp: float | None = None) -> MonitorEvent:
        """Process one tool call. Returns MonitorEvent (with alert flag if anomalous).

        Prequential: scores BEFORE updating the model, so the first call can
        already be scored (though always in warmup / non-alerting mode).
        """
        args = args or {}
        now  = timestamp if timestamp is not None else time.time()

        # 1. Extract features (prequential — score first, then update state)
        fv = self._featurizer.observe(tool_name, args, now=now)

        # 2. Normalize to [0,1]
        vec = self._normalizer.update_and_normalize(fv.to_vector())

        # 3. Score + learn (Layer 2 — unsupervised anomaly)
        score = self._detector.score_and_learn(vec)

        n = len(self.events)          # events seen BEFORE this one
        in_warmup = n < self.warmup_events

        # 3b. Layer-0 deterministic toxic-transition rule (Blueprint §6.2).
        # The runtime lethal trifecta: a secret was recently read AND this event
        # is external egress. This is "THE signal" the blueprint calls out that
        # unsupervised density estimation (Layer 2) systematically misses,
        # because the exfil event differs from normal on only 1-2 dimensions.
        # Deterministic rules fire immediately (no warmup, no baseline needed).
        deterministic_risk = 0.0
        secret_recent = (n - self._last_secret_read_at) <= _SECRET_RECENCY_WINDOW
        if _is_egress_event(tool_name, fv.event_key) and secret_recent:
            # Confidence scales with how surprising the transition is, floored at
            # 0.9 (this is a hard signal). Uses a NARROW secret definition — a
            # true credential/key/secret read within the recency window, not any
            # file read — so benign read_file→API-call flows do not trip it.
            deterministic_risk = min(1.0, 0.9 + 0.1 * min(fv.transition_surprisal, 1.0))
        # Record a true-secret read for the NEXT events' recency check.
        if _is_secret_read(tool_name):
            self._last_secret_read_at = n

        # 3c. Role-relative deviation (the per-role-baseline / network-effect
        # signal). A session can be INTERNALLY consistent — so the self-adapting
        # unsupervised detector sees nothing — yet be far outside what this ROLE
        # normally does. We detect that via a one-sided proportion test (Wilson).
        # Question: is THIS session's egress RATE confidently above the ROLE's
        # normal rate, given how many events we've seen? This is robust to two
        # things a per-event threshold is not:
        #   - opening bursts: few events → wide interval → low bound → no fire;
        #   - benign bursts mid-session: a transient run barely moves the
        #     cumulative proportion, so the bound stays below the role rate.
        # It fires only when SUSTAINED egress is confidently role-abnormal.
        # Update cumulative counts first (this event counts).
        is_external = fv.event_key.endswith(":external")
        self._cum_total += 1
        if is_external:
            self._cum_external += 1

        role_deviation_risk = 0.0
        if (self.role_deviation
                and self._role_egress_rate is not None
                and self._cum_total >= _ROLE_DEV_MIN_EVENTS):
            wilson_lo = _wilson_lower_bound(self._cum_external, self._cum_total)
            session_frac = self._cum_external / self._cum_total
            p_role = self._role_egress_rate
            if (wilson_lo > p_role + _ROLE_DEV_MARGIN
                    and session_frac >= _ROLE_DEV_ABS_FLOOR):
                # Passing a 95% one-sided proportion test that the session's
                # egress rate exceeds the role's IS alert-worthy on its own, so
                # floor the risk above the alert threshold and scale up with the
                # severity of the gap. (Normalizing by headroom alone could leave
                # a genuine, confident deviation just under threshold.)
                gap = (wilson_lo - p_role) / max(1.0 - p_role, 1e-6)
                role_deviation_risk = min(1.0, 0.75 + 0.25 * gap)
                self._role_deviation_fired = True

        # 4. Combine: max of anomaly score and both deterministic signals.
        if not in_warmup:
            self._warmed_up = True

        # Anomaly component is suppressed during warmup; the deterministic rules
        # are NOT (they need no per-session baseline). Alert if any crosses thresh.
        anomaly_component = 0.0 if in_warmup else score.score
        combined = max(anomaly_component, deterministic_risk, role_deviation_risk)
        is_alert = combined > score.threshold

        score = AnomalyScore(
            score=combined,
            hst_score=score.hst_score,
            loda_score_normalized=score.loda_score_normalized,
            feature_contributions=score.feature_contributions,
            is_anomalous=is_alert,
            threshold=score.threshold,
        )

        event = MonitorEvent(
            tool_name=tool_name,
            args=args,
            timestamp=now,
            features=fv,
            score=score,
        )
        self.events.append(event)
        if event.alert:
            self.alerts.append(event)
        return event

    def summary(self) -> dict:
        return {
            "session_id": self.session_id,
            "role": self.role,
            "total_events": len(self.events),
            "alerts": len(self.alerts),
            "warmed_up": self._warmed_up,
            "alert_events": [
                {
                    "tool": e.tool_name,
                    "score": round(e.score.score, 3),
                    "event_key": e.features.event_key,
                    "top_drivers": e.top_contributing_features,
                }
                for e in self.alerts
            ],
        }


class AgentMonitor:
    """Per-role behavioral monitor. One instance per agent role.

    Maintains the role prior (mean + std of feature values from past sessions)
    and produces MonitorSessions for each new agent execution.

    The role prior enables z-score features and improves cold-start behavior:
    a new session inherits the role's known-normal distribution from day one.

    Blueprint §6.2: "federated role baselines — the data network effect."
    """

    def __init__(self,
                 role: str = "default",
                 threshold: float = 0.75,
                 warmup_events: int = DEFAULT_WARMUP_EVENTS,
                 hst_window: int = 100,
                 baseline_manager=None,
                 role_deviation: bool = True,
                 drift_delta: float = 5.0,
                 drift_threshold: float = 20.0,
                 drift_burn_in: int = 12):
        self.role          = role
        self.threshold     = threshold
        self.warmup_events = warmup_events
        self.hst_window    = hst_window
        self.role_deviation = role_deviation
        # Session-level concept-drift detector (Page-Hinkley over the per-session
        # MEAN anomaly score, on a 0-100 scale). Watches for a SUSTAINED shift in
        # the agent's anomaly baseline across sessions — a legitimate "new normal"
        # (model upgrade, new tool, workflow change) that should trigger baseline
        # RE-LEARNING rather than an alert flood. A one-off attack is a transient
        # spike that does not sustain the statistic, so it is left to the
        # point-anomaly layer and never surfaces here as drift. Defaults are
        # calibrated for the 0-100 session-mean scale (delta 5, threshold 20 →
        # 0% false-drift, ~4-session delay; see benchmarks/drift_eval.py). The
        # investigate/reset boundary is tied to the point-alert threshold.
        self._drift = DriftMonitor(
            threshold=drift_threshold,
            burn_in=drift_burn_in,
            delta=drift_delta,
            investigate_level=threshold * 100.0,
        )
        # Optional RoleBaselineManager (behavioral/baselines.py) for cross-session,
        # empirical-Bayes-shrunk, persistent role priors — the federated-baseline
        # data network effect. When present, new sessions inherit the learned prior.
        self.baseline_manager = baseline_manager
        self._role_prior:  dict[str, tuple[float, float]] | None = None
        self._sessions:    list[MonitorSession] = []
        # Role egress rate = mean TRUE cumulative external/total fraction over
        # learned sessions — the same statistic the Wilson deviation test uses.
        # None until at least one benign session is learned.
        self._role_egress_rates: list[float] = []
        self._role_egress_rate: float | None = None

    def new_session(self, session_id: str = "") -> MonitorSession:
        """Create a new MonitorSession for one agent execution."""
        prior = self._role_prior
        if self.baseline_manager is not None:
            mgr_prior = self.baseline_manager.prior_for(self.role)
            if mgr_prior:
                prior = mgr_prior
        session = MonitorSession(
            session_id=session_id or f"session-{len(self._sessions)}",
            role=self.role,
            role_prior=prior,
            threshold=self.threshold,
            warmup_events=self.warmup_events,
            hst_window=self.hst_window,
            role_deviation=self.role_deviation,
            role_egress_rate=self._role_egress_rate,
        )
        self._sessions.append(session)
        return session

    def learn_from(self, *sessions: MonitorSession, skip_flagged: bool = True) -> None:
        """Fold completed sessions into the role prior via the baseline manager.

        This is how the network effect compounds: each benign session refines
        the role's known-normal distribution (empirical-Bayes shrinkage), so the
        next session starts warm instead of cold.

        ANTI-POISONING GUARD (skip_flagged, default True): never fold a session
        whose egress rate the ROLE-DEVIATION (Wilson) signal already judged
        role-abnormal (`_role_deviation_fired`) back into the role's egress-rate
        baseline. This is circular-reasoning / self-poisoning prevention: the
        Wilson test says "this session's egress rate is confidently ABOVE the
        role's normal", so letting that same session redefine "the role's normal"
        upward is exactly how an adaptive attacker evades it.
        WHY THIS IS THE RIGHT DISCRIMINATOR: the session-level drift detector
        recommends "reset_baseline" for a legitimate new normal, but it
        classifies on the scalar mean anomaly score, which CANNOT distinguish a
        benign new-normal (drift_eval: regime mean ~48) from an adaptive attacker
        slowly ramping egress to poison the baseline (measured regime mean ~44 —
        overlapping, both below investigate_level). So the reset recommendation
        cannot be trusted to gate re-learning. The role-deviation flag CAN: a
        benign new-normal shifts the anomaly mean without its cumulative egress
        rate being role-abnormal, whereas an egress-ramp poisoning attempt trips
        the Wilson test once its rate clears the role floor. Measured: excluding
        these sessions keeps the role egress rate at ~0.03 instead of it being
        poisoned to ~0.33, with NO benign-FP cost — benign sessions (incl. ones
        that legitimately trip Layer-0 secret->egress, e.g. data_analyst) do not
        trip role-deviation, so they are still learned normally. A flagged
        session is excluded from BOTH the egress-rate estimate and the feature
        prior (a role-abnormal session should teach neither); benign sessions are
        never excluded because they never trip the role-deviation signal.
        """
        learn = [s for s in sessions
                 if not (skip_flagged and s._role_deviation_fired)]
        # Learn the role's true egress rate (same statistic the Wilson test uses),
        # regardless of which prior backend is in use.
        for s in learn:
            if s._cum_total > 0:
                self._role_egress_rates.append(s.egress_fraction)
        if self._role_egress_rates:
            self._role_egress_rate = sum(self._role_egress_rates) / len(self._role_egress_rates)

        if self.baseline_manager is None:
            # Fall back to the built-in plain mean/std prior.
            self.update_role_prior(*learn)
            return
        for s in learn:
            vectors = [e.features.to_vector() for e in s.events]
            if vectors:
                self.baseline_manager.observe_session(self.role, vectors)

    def update_role_prior(self, *sessions: MonitorSession) -> None:
        """Update the role prior from the given completed sessions.

        Call this after each session ends to improve future sessions' cold-start.
        In production this would aggregate across all customers of this role
        (the federated baseline network effect).
        """
        all_vectors: list[list[float]] = []
        for s in sessions:
            for e in s.events:
                all_vectors.append(e.features.to_vector())

        if not all_vectors:
            return

        dim = len(all_vectors[0])
        n   = len(all_vectors)
        means = [sum(v[i] for v in all_vectors) / n for i in range(dim)]
        stds  = [
            (sum((v[i] - means[i]) ** 2 for v in all_vectors) / max(n - 1, 1)) ** 0.5
            for i in range(dim)
        ]
        self._role_prior = {
            FEATURE_NAMES[i]: (means[i], max(stds[i], 1e-9))
            for i in range(dim)
        }

    def observe_session_drift(self, session: MonitorSession) -> DriftEvent | None:
        """Feed a COMPLETED session's mean anomaly score to the session-level
        Page-Hinkley drift detector, and surface a classified DriftEvent when a
        sustained cross-session shift in the anomaly baseline is detected.

        Call this once per session after it ends (the drift signal is the stream
        of per-session mean anomaly scores — "the baseline drifts over many
        sessions"). Per-EVENT scores are too noisy to drift on directly; the
        per-session mean is the stable signal.

        Returns:
            DriftEvent (recommendation "reset_baseline" for a benign new normal,
            or "investigate" for a sustained high-anomaly regime) when drift is
            confirmed, else None. A one-off attack session is a transient spike
            that does not sustain the statistic → returns None (handled by the
            point-anomaly layer).
        """
        if not session.events:
            return None
        mean_score = sum(e.score.score for e in session.events) / len(session.events)
        # 0-1 anomaly score → 0-100 scale the detector's delta/threshold assume.
        return self._drift.observe(self.role, int(round(mean_score * 100)))

    def reset_drift(self) -> None:
        """Reset the session-level drift detector (after re-learning the baseline)."""
        self._drift.reset_agent(self.role)

    @property
    def drift_events(self) -> list[DriftEvent]:
        """All confirmed session-level drift events for this role."""
        return self._drift.drift_events

    def global_summary(self) -> dict:
        total_events = sum(len(s.events) for s in self._sessions)
        total_alerts = sum(len(s.alerts) for s in self._sessions)
        return {
            "role": self.role,
            "sessions": len(self._sessions),
            "total_events": total_events,
            "total_alerts": total_alerts,
            "alert_rate": round(total_alerts / max(total_events, 1), 4),
            "role_prior": self._role_prior,
        }


# ---------------------------------------------------------------------------
# Convenience: run a list of (tool_name, args, timestamp) through a session
# ---------------------------------------------------------------------------

def replay_trace(trace: list[dict], role: str = "default",
                 threshold: float = 0.75,
                 warmup_events: int = DEFAULT_WARMUP_EVENTS) -> MonitorSession:
    """Replay a trace of tool calls through a new MonitorSession.

    trace items: {"tool": str, "args": dict, "t": float}

    Returns the completed session (inspect .alerts for detections).

    Useful for offline evaluation and for replay-testing the detector
    against known-bad traces.
    """
    monitor = AgentMonitor(role=role, threshold=threshold,
                           warmup_events=warmup_events)
    session = monitor.new_session("replay")
    for item in trace:
        session.observe(
            tool_name=item.get("tool", "unknown"),
            args=item.get("args", {}),
            timestamp=item.get("t"),
        )
    return session
