"""Behavioral risk scoring — statistical deviation-from-baseline (NOT trained ML).

HONEST LABEL (corrected in Phase 0). This module is **not** an Isolation Forest,
an autoencoder, or any trained/learned model — those names appeared in the previous
docstring but no such model exists in the code. It is a **hand-weighted statistical
anomaly scorer**: it builds a per-agent baseline of observed behavior, then measures
how far a new action deviates from it. The combination weights below are set by hand,
not fit to data, and the score has **not** been calibrated against a labeled corpus.
Treat the 0-99 output as a heuristic signal, not a probability.

What it actually computes:
1. A per-agent baseline (running frequency / timing / parameter statistics).
2. Five deviation heuristics — frequency, temporal, parameter, structural,
   sequence-transition — each returning a 0-99 sub-score + human-readable factors.
3. A fixed weighted average [0.20, 0.15, 0.15, 0.30, 0.20] with a max-model floor.

This is a legitimate but simple *unsupervised deviation* approach. It maps to the
Blueprint's day-one "rules + unsupervised deviation-from-normal" layer — NOT to the
trained HST/LODA/DeepLog→XGBoost pipeline (THE_BLUEPRINT §6.2), which is future work
gated on labeled data. Do not market this as machine learning.

Modes:
- Baselining: accumulate normal observations per agent (`learn`).
- Scoring: deviation of a new action from that baseline (`score`).
"""

import math
from dataclasses import dataclass, field

from lucin.behavioral.features import ActionFeatures


@dataclass
class RiskScore:
    """The output of the scoring engine — a single risk assessment."""
    score: int  # 0-99 (0 = definitely normal, 99 = definitely anomalous)
    confidence: float  # 0.0-1.0 (how confident are we in this score?)
    contributing_factors: list[str] = field(default_factory=list)  # Why this score?
    recommended_action: str = "allow"  # allow, alert, escalate, block

    @property
    def action_threshold(self) -> str:
        """Recommended action based on score."""
        if self.score < 30:
            return "allow"
        elif self.score < 60:
            return "alert"
        elif self.score < 85:
            return "escalate"
        else:
            return "block"


class BehavioralScorer:
    """The ensemble scoring engine.

    Production usage:
        scorer = BehavioralScorer()
        scorer.learn(normal_action_features)  # Train on normal behavior
        ...
        risk = scorer.score(new_action_features)  # Score new action
        if risk.score > 70:
            trigger_alert(risk)
    """

    def __init__(self):
        # Per-agent baselines: agent_id -> learned baseline stats
        self._baselines: dict[str, AgentBaseline] = {}
        # Global statistics across all agents (for peer comparison)
        self._global_stats = GlobalStats()

    def learn(self, features: ActionFeatures) -> None:
        """Update the baseline with a new normal observation.

        Called during the baselining period (first 30-60 days)
        and continuously afterward for online learning.
        """
        agent_id = features.agent_id

        if agent_id not in self._baselines:
            self._baselines[agent_id] = AgentBaseline(agent_id=agent_id)

        baseline = self._baselines[agent_id]
        baseline.update(features)
        self._global_stats.update(features)

    def score(self, features: ActionFeatures) -> RiskScore:
        """Score a new action against the learned baseline.

        Returns a 0-99 risk score with explanation.
        This is the inference step — must be <50ms.
        """
        agent_id = features.agent_id
        baseline = self._baselines.get(agent_id)

        if baseline is None or baseline.observation_count < 10:
            # Cold start: not enough data to score meaningfully
            # Use global statistics + structural checks only
            return self._cold_start_score(features)

        # === ENSEMBLE SCORING ===
        scores = []
        factors = []

        # Model 1: Frequency anomaly (is this tool call unusual for this agent?)
        freq_score, freq_factors = self._frequency_anomaly(features, baseline)
        scores.append(freq_score)
        factors.extend(freq_factors)

        # Model 2: Temporal anomaly (is the timing unusual?)
        temp_score, temp_factors = self._temporal_anomaly(features, baseline)
        scores.append(temp_score)
        factors.extend(temp_factors)

        # Model 3: Parameter anomaly (are the params unusual?)
        param_score, param_factors = self._parameter_anomaly(features, baseline)
        scores.append(param_score)
        factors.extend(param_factors)

        # Model 4: Structural risk (regardless of baseline — inherently dangerous?)
        struct_score, struct_factors = self._structural_risk(features)
        scores.append(struct_score)
        factors.extend(struct_factors)

        # Model 5: SEQUENCE anomaly (is this tool-call TRANSITION unusual?)
        # Per TraceAegis: scoring actions independently misses attack patterns
        # that are only visible as SEQUENCES (e.g., read_db → send_http)
        seq_score, seq_factors = self._sequence_anomaly(features, baseline)
        scores.append(seq_score)
        factors.extend(seq_factors)

        # === ENSEMBLE COMBINATION ===
        # Use BOTH weighted average AND max-model floor.
        # This prevents a single high-confidence model from being diluted
        # by other models that simply don't have signal.
        # (Same principle as fraud detection: one strong signal shouldn't be averaged away)
        weights = [0.20, 0.15, 0.15, 0.30, 0.20]  # freq, temporal, param, structural, sequence
        weighted_avg = sum(s * w for s, w in zip(scores, weights))

        # Floor: highest individual model score * 0.7
        # (A single model saying "definitely anomalous" gets at least 70% of its score through)
        # In fraud detection, a single strong signal should not be averaged away by null signals
        max_model_floor = max(scores) * 0.7

        combined = max(weighted_avg, max_model_floor)

        # Calibrate to 0-99
        final_score = min(99, max(0, int(combined)))

        # Confidence based on baseline maturity
        confidence = min(1.0, baseline.observation_count / 100)

        return RiskScore(
            score=final_score,
            confidence=confidence,
            contributing_factors=factors[:5],  # Top 5 factors
            recommended_action=RiskScore(score=final_score, confidence=confidence).action_threshold,
        )

    def _cold_start_score(self, features: ActionFeatures) -> RiskScore:
        """Score with no baseline data — use structural heuristics only."""
        score = 0
        factors = []

        if features.tool_is_high_risk:
            score += 30
            factors.append("High-risk tool type (exec/network/write)")
        if features.params_contain_sensitive_keywords:
            score += 20
            factors.append("Parameters contain sensitive keywords")
        if features.params_contain_url and features.tool_is_high_risk:
            score += 15
            factors.append("URL in parameters of high-risk tool")
        if not features.action_after_user_message:
            score += 10
            factors.append("Autonomous action (not triggered by user)")
        if features.delegation_depth > 2:
            score += 10
            factors.append(f"Deep delegation chain (depth: {features.delegation_depth})")

        return RiskScore(
            score=min(99, score),
            confidence=0.3,  # Low confidence — no baseline
            contributing_factors=factors,
            recommended_action="alert" if score > 40 else "allow",
        )

    def _frequency_anomaly(self, features: ActionFeatures, baseline: 'AgentBaseline') -> tuple[int, list[str]]:
        """How unusual is this tool call frequency?"""
        score = 0
        factors = []

        if features.tool_is_new_for_agent:
            score += 70
            factors.append(f"First-ever use of this tool by this agent")
        elif features.tool_frequency_for_agent < 0.01:
            score += 50
            factors.append(f"Rarely-used tool (frequency: {features.tool_frequency_for_agent:.3f})")

        # Velocity anomaly (too many calls too fast)
        if features.actions_in_last_minute > 5:
            # Extremely rapid — more than 5 actions per minute is unusual for most agents
            score += 50
            factors.append(
                f"Extreme velocity: {features.actions_in_last_minute} actions/min "
                f"(baseline avg: {baseline.avg_actions_per_minute:.1f}/min)"
            )
        elif features.actions_in_last_minute > baseline.avg_actions_per_minute * 3 and baseline.avg_actions_per_minute > 0:
            score += 30
            factors.append(
                f"Action velocity 3x above baseline "
                f"({features.actions_in_last_minute}/min vs avg {baseline.avg_actions_per_minute:.1f}/min)"
            )

        return min(99, score), factors

    def _temporal_anomaly(self, features: ActionFeatures, baseline: 'AgentBaseline') -> tuple[int, list[str]]:
        """How unusual is the timing?"""
        score = 0
        factors = []

        # Check if this hour is unusual for the agent
        hour_frequency = baseline.hour_distribution.get(features.hour_of_day, 0)
        if hour_frequency < 0.02:  # This hour represents <2% of activity
            score += 30
            factors.append(f"Unusual hour ({features.hour_of_day}:00 — rare for this agent)")

        # Check inter-action timing
        if features.seconds_since_last_action < 0.1 and features.tool_is_high_risk:
            score += 25
            factors.append("Rapid-fire high-risk tool calls (<100ms apart)")

        return min(99, score), factors

    def _parameter_anomaly(self, features: ActionFeatures, baseline: 'AgentBaseline') -> tuple[int, list[str]]:
        """How unusual are the parameters?"""
        score = 0
        factors = []

        # High entropy parameters (might be encoded/encrypted data)
        if features.param_entropy > 5.0 and baseline.avg_param_entropy < 3.5:
            score += 30
            factors.append(
                f"High parameter entropy ({features.param_entropy:.1f} vs baseline {baseline.avg_param_entropy:.1f})"
            )

        # Unusually large parameters
        if features.param_total_length > baseline.avg_param_length * 5:
            score += 20
            factors.append("Parameter size 5x above baseline")

        # Contains sensitive keywords (and this is unusual for this agent)
        if features.params_contain_sensitive_keywords and not baseline.usually_accesses_sensitive:
            score += 35
            factors.append("Sensitive keywords in parameters (unusual for this agent)")

        return min(99, score), factors

    def _sequence_anomaly(self, features: ActionFeatures, baseline: 'AgentBaseline') -> tuple[int, list[str]]:
        """How unusual is this tool call as part of a SEQUENCE?

        Per TraceAegis (arXiv:2510.11203): scoring actions independently misses
        attack patterns that are only visible as transitions.

        Key insight: "read_database → send_http" is individually normal but
        the TRANSITION is the exfiltration pattern.
        """
        score = 0
        factors = []

        agent_id = features.agent_id
        current_tool = features.tool_name_encoded

        # Get the previous tool from the baseline's sequence history.
        # last_tools / transition_counts are real serializable fields (they
        # survive save/load), so no hasattr bootstrapping is needed.
        if baseline.last_tools:
            prev_tool = baseline.last_tools[-1]
            transition = f"{prev_tool}→{current_tool}"

            total_transitions = sum(baseline.transition_counts.values()) or 1
            this_transition_count = baseline.transition_counts.get(transition, 0)
            transition_freq = this_transition_count / total_transitions

            # Novel transition (never seen before after baseline period)
            if this_transition_count == 0 and baseline.observation_count > 50:
                score += 40
                factors.append(f"Novel tool transition (never seen in {baseline.observation_count} observations)")

            # Rare transition (seen but very uncommon)
            elif transition_freq < 0.01 and baseline.observation_count > 50:
                score += 25
                factors.append(f"Rare tool transition (frequency: {transition_freq:.4f})")

            # Track this transition for learning
            baseline.transition_counts[transition] = this_transition_count + 1

        # (Removed dead `DANGEROUS_TRANSITIONS` dict here in Phase 0 — it was defined
        # but never referenced; the high-risk sequence signal below is what actually
        # fires. A real known-bad-transition table belongs in the trained pipeline.)
        if features.tool_is_high_risk and features.tool_is_new_for_agent:
            if len(baseline.last_tools) >= 2:
                # Rapid sequence of new high-risk tools = attack chain
                score += 30
                factors.append("Sequence of new high-risk tools (potential attack chain)")

        # Update sequence history (keep last 10)
        baseline.last_tools.append(current_tool)
        if len(baseline.last_tools) > 10:
            baseline.last_tools = baseline.last_tools[-10:]

        return min(99, score), factors

    def _structural_risk(self, features: ActionFeatures) -> tuple[int, list[str]]:
        """Inherent risk regardless of baseline (always dangerous patterns)."""
        score = 0
        factors = []

        # New tool + high risk + autonomous = very concerning
        if features.tool_is_new_for_agent and features.tool_is_high_risk and not features.action_after_user_message:
            score += 70
            factors.append("NEW high-risk tool called AUTONOMOUSLY (not triggered by user)")

        # Data access + network in same session = exfiltration pattern
        if features.params_contain_sensitive_keywords and features.params_contain_url:
            score += 50
            factors.append("Sensitive data keywords + URL in same action (exfiltration pattern)")

        # Deep delegation + high risk = potential attack chain
        if features.delegation_depth > 2 and features.tool_is_high_risk:
            score += 30
            factors.append(f"High-risk tool at delegation depth {features.delegation_depth}")

        return min(99, score), factors

    @property
    def baseline_count(self) -> int:
        """Number of agents with established baselines."""
        return len(self._baselines)


@dataclass
class AgentBaseline:
    """Learned behavioral baseline for a single agent."""
    agent_id: str
    observation_count: int = 0
    avg_actions_per_minute: float = 0.0
    avg_param_length: float = 100.0
    avg_param_entropy: float = 3.0
    hour_distribution: dict[int, float] = field(default_factory=lambda: {h: 1/24 for h in range(24)})
    tool_frequencies: dict[str, float] = field(default_factory=dict)
    usually_accesses_sensitive: bool = False
    # Sequence memory — promoted from ad-hoc `hasattr`-created attributes to
    # real, serializable fields so the learned tool-transition graph survives a
    # save/load cycle (previously it was silently dropped on restart).
    last_tools: list[int] = field(default_factory=list)          # recent tool encodings
    transition_counts: dict[str, int] = field(default_factory=dict)  # "prev→cur" -> count
    _tool_counts: dict[str, int] = field(default_factory=dict)   # encoded tool -> raw count

    def update(self, features: ActionFeatures) -> None:
        """Online update with a new observation."""
        self.observation_count += 1
        n = self.observation_count

        # Running averages (online update — no batch needed)
        self.avg_param_length += (features.param_total_length - self.avg_param_length) / n
        self.avg_param_entropy += (features.param_entropy - self.avg_param_entropy) / n
        # Learn the baseline action velocity so the "velocity 3x above baseline"
        # branch in _frequency_anomaly actually has a non-zero reference to
        # compare against (previously this stayed 0.0 forever → dead branch).
        self.avg_actions_per_minute += (
            features.actions_in_last_minute - self.avg_actions_per_minute) / n

        # Learn per-tool frequency (persisted across restarts, keyed by the
        # stable tool encoding). Previously never populated → dead field.
        key = str(features.tool_name_encoded)
        self._tool_counts[key] = self._tool_counts.get(key, 0) + 1
        for k, c in self._tool_counts.items():
            self.tool_frequencies[k] = c / n

        # Update hour distribution
        for h in range(24):
            if h == features.hour_of_day:
                self.hour_distribution[h] += (1.0 - self.hour_distribution.get(h, 0)) / n
            else:
                self.hour_distribution[h] = self.hour_distribution.get(h, 0) * (n - 1) / n

        # Track sensitivity access patterns
        if features.params_contain_sensitive_keywords:
            self.usually_accesses_sensitive = True


@dataclass
class GlobalStats:
    """Aggregated statistics across all agents (for peer comparison)."""
    total_observations: int = 0
    tool_usage_rates: dict[str, float] = field(default_factory=dict)

    def update(self, features: ActionFeatures) -> None:
        self.total_observations += 1
