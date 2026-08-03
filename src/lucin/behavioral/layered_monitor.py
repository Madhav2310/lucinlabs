"""MATURITY: L2 (scaffolded + unit-tested on author input; NOT validated on real agent traces).

LayeredMonitor — composes AgentMonitor (behavioral scoring) with the Page-Hinkley
drift detector AND an optional Layer-1 admission gate for untrusted input, without
modifying any of them.

AgentMonitor scores each event for point anomalies (Layer-0 toxic-transition +
Layer-2 streaming anomaly). drift.PageHinkleyDetector watches the *stream* of those
scores for a sustained shift in the mean — i.e. the agent's "normal" moved (a model
upgrade, a new tool, a workflow change) rather than a single weird call. Separating
the two matters: a legitimate drift should trigger baseline re-learning, not an
alert flood.

Layer-1 (admission gate) is the *input* screen: many agent compromises arrive not as
an anomalous ACTION but as an injection carried on untrusted content that ENTERS the
agent — a tool RETURN, a retrieved document, an inbound message. Behavioral layers
see the resulting action (which may look normal); Layer-1 catches the poisoned input
BEFORE it steers the agent. It reuses guard.injection_detector.build_admission_gate
(regex committee + trained TF-IDF detector when its assets are present), so it needs
no torch/network. It is RAISE-ONLY and OPTIONAL: absent a trained head it degrades to
the pure-regex gate, and if the gate cannot be built at all it is skipped — no crash.

This class owns none of AgentMonitor / PageHinkleyDetector / AdmissionGate internals.
It forwards each observed event to a MonitorSession, feeds the resulting anomaly score
into the drift detector, and (when untrusted content is supplied) screens that content
with the admission gate. monitor.py, drift.py and guard/ are untouched.

    lm = LayeredMonitor(role="support")
    for tool, args, t, tool_return in stream:
        ev = lm.observe(tool, args, t, untrusted_content=tool_return)
        if ev.alert:                        # composed: Layer-0/1/2 rolled up
            handle_alert(ev)
        if lm.drift_detected:
            handle_drift(lm.drift_points)
"""

from __future__ import annotations

from lucin.behavioral.drift import PageHinkleyDetector
from lucin.behavioral.monitor import AgentMonitor, MonitorEvent, MonitorSession

# AnomalyScore.score is in [0, 1]; drift.py's Page-Hinkley defaults (threshold 15,
# delta 0.01) are documented against a 0-99 score scale, so we rescale.
_SCORE_SCALE = 100.0

# Reserved key on an event's `args` that carries untrusted content entering the agent
# (a tool RETURN / retrieved document / inbound message). Deliberately a single
# reserved name — NOT a scan of arbitrary arg keys — so existing traces whose args
# carry ordinary tool INPUTS (query, url, host, ...) are never screened and behavior
# is unchanged when no untrusted content is declared. The explicit `untrusted_content`
# kwarg on observe() takes precedence over this key.
_UNTRUSTED_ARG_KEY = "untrusted_content"


class LayeredMonitor:
    """Point-anomaly scoring (AgentMonitor) + stream drift detection (Page-Hinkley).

    Composition only — does not subclass or mutate AgentMonitor / PageHinkleyDetector.
    """

    def __init__(
        self,
        role: str = "default",
        threshold: float = 0.75,
        warmup_events: int | None = None,
        hst_window: int = 100,
        role_prior: dict[str, tuple[float, float]] | None = None,
        drift_delta: float = 0.01,
        drift_threshold: float = 15.0,
        drift_burn_in: int = 30,
        screen_untrusted_input: bool = True,
        admission_gate=None,
    ) -> None:
        kwargs: dict = {"role": role, "threshold": threshold, "hst_window": hst_window}
        if warmup_events is not None:
            kwargs["warmup_events"] = warmup_events
        self._monitor = AgentMonitor(**kwargs)
        # Seed the role prior if provided (AgentMonitor exposes it as _role_prior;
        # we set it before creating the session so the session inherits it).
        if role_prior is not None:
            self._monitor._role_prior = role_prior
        self._session: MonitorSession = self._monitor.new_session()

        self._drift = PageHinkleyDetector(
            delta=drift_delta, threshold=drift_threshold, burn_in=drift_burn_in
        )
        self._drift_points: list[int] = []
        self._n: int = 0

        # Layer-1 (admission gate) — optional, lazily built on first use so
        # constructing a LayeredMonitor stays cheap and cannot fail on gate import.
        self._screen_untrusted = screen_untrusted_input
        self._admission_gate = admission_gate
        self._gate_built = admission_gate is not None
        self._layer1_available: bool | None = None if admission_gate is None else True
        self._layer1_points: list[int] = []

    def _ensure_gate(self):
        """Lazily build the admission gate (regex committee + trained detector if
        its assets are present). Never raises: on any failure Layer-1 is skipped."""
        if self._gate_built:
            return self._admission_gate
        self._gate_built = True
        try:
            from lucin.guard.injection_detector import build_admission_gate
            self._admission_gate = build_admission_gate()
        except Exception:  # noqa: BLE001 — Layer-1 is optional; degrade to skipped.
            self._admission_gate = None
        self._layer1_available = self._admission_gate is not None
        return self._admission_gate

    def _extract_untrusted(self, args: dict | None,
                           untrusted_content: str | None) -> str | None:
        """Untrusted content is the explicit kwarg, else a single RESERVED args key.
        Ordinary tool-INPUT args are never treated as untrusted input."""
        if untrusted_content is not None:
            return untrusted_content
        if isinstance(args, dict):
            v = args.get(_UNTRUSTED_ARG_KEY)
            if isinstance(v, str):
                return v
        return None

    def observe(self, tool_name: str, args: dict | None = None,
                timestamp: float | None = None,
                untrusted_content: str | None = None) -> MonitorEvent:
        """Forward one tool call to the session, feed its score to the drift detector,
        and (Layer-1) screen any untrusted content that arrived on this event.

        `untrusted_content` (or an ``args["untrusted_content"]`` field) is content
        ENTERING the agent — a tool return, a retrieved document, an inbound message.
        If the admission gate does NOT admit it (injection indicators), Layer-1 fires:
        the event is composed to `alert=True` alongside Layer-0/2. When no untrusted
        content is supplied, Layer-1 is a no-op and behavior is exactly as before.
        """
        event = self._session.observe(tool_name, args=args, timestamp=timestamp)
        self._n += 1
        # Drift is fed the BEHAVIORAL score only (Layer-0/2). A content injection is
        # not a behavioral-baseline shift, so it must not perturb the drift signal.
        drifted = self._drift.update(event.score.score * _SCORE_SCALE)
        if drifted:
            self._drift_points.append(self._n - 1)  # 0-based index of the drifting event

        # Layer-1: screen untrusted input carried on this event.
        event.layer1_flagged = False          # dynamic attr; MonitorEvent is unslotted
        event.layer1_decision = None
        content = self._extract_untrusted(args, untrusted_content) if self._screen_untrusted else None
        if content:
            gate = self._ensure_gate()
            if gate is not None:
                try:
                    decision = gate.admit(content)
                except Exception:  # noqa: BLE001 — never let Layer-1 break observation.
                    decision = None
                if decision is not None:
                    event.layer1_decision = decision
                    # Fire whenever the gate does NOT ADMIT the content — a block OR
                    # an abstain (both set allow=False). With the TRAINED detector the
                    # gate collapses its abstention band to the calibrated threshold,
                    # so benign content stays admitted at the ~1% FP budget; with the
                    # regex-only fallback the band is what lets overt injections that
                    # score in [0.30,0.60) still raise a signal rather than pass.
                    if not decision.allow:
                        event.layer1_flagged = True
                        self._layer1_points.append(self._n - 1)
                        # Compose Layer-1 into the event's alert (roll up with 0/2).
                        event.score.is_anomalous = True
        return event

    @property
    def drift_detected(self) -> bool:
        """True if Page-Hinkley has flagged a sustained shift since the last reset."""
        return bool(self._drift.is_drifting)

    @property
    def drift_points(self) -> list[int]:
        """Event indices (0-based) at which drift was flagged."""
        return list(self._drift_points)

    @property
    def layer1_flagged(self) -> bool:
        """True if the admission gate blocked untrusted content on any event so far."""
        return bool(self._layer1_points)

    @property
    def layer1_points(self) -> list[int]:
        """Event indices (0-based) at which Layer-1 blocked untrusted input."""
        return list(self._layer1_points)

    @property
    def layer1_available(self) -> bool | None:
        """None until the gate is first built; then True (gate built, possibly
        regex-only) or False (gate could not be constructed → Layer-1 skipped)."""
        return self._layer1_available

    @property
    def session(self) -> MonitorSession:
        return self._session

    @property
    def monitor(self) -> AgentMonitor:
        return self._monitor

    def reset_drift(self) -> None:
        """Reset the drift detector (e.g. after re-learning the baseline)."""
        self._drift.reset()
