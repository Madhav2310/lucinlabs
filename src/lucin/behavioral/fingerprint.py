"""Agent Behavioral Fingerprinting — unique signature per agent instance.

Creates a compact behavioral fingerprint for each agent based on:
- Tool usage distribution (which tools, how often)
- Temporal patterns (when active, inter-action timing)
- Parameter characteristics (typical lengths, entropy levels)
- Sequence patterns (common tool-call orderings)

Use cases:
1. Detect agent impersonation (one agent mimicking another)
2. Detect agent hijacking (fingerprint suddenly changes)
3. Compare agents to peer groups (cluster similar agents)
4. Verify agent identity (is this really Agent X?)

The fingerprint is a fixed-size vector that captures the agent's
behavioral "DNA" — stable over time for legitimate agents, but
changes dramatically if the agent is compromised or replaced.
"""

import math
from collections import Counter
from dataclasses import dataclass, field

from lucin.behavioral.features import AgentAction


@dataclass
class AgentFingerprint:
    """Compact behavioral signature of an agent."""
    agent_id: str
    observation_count: int = 0

    # Tool usage distribution (normalized frequencies)
    tool_distribution: dict[str, float] = field(default_factory=dict)

    # Temporal signature
    avg_actions_per_hour: float = 0.0
    active_hours: list[int] = field(default_factory=list)  # Hours with activity (0-23)
    avg_inter_action_seconds: float = 0.0

    # Parameter signature
    avg_param_length: float = 0.0
    avg_param_entropy: float = 0.0

    # Sequence signature (top 5 most common transitions)
    common_transitions: list[tuple[str, str, float]] = field(default_factory=list)

    def similarity(self, other: 'AgentFingerprint') -> float:
        """Compute cosine similarity between two fingerprints (0.0 to 1.0).

        1.0 = identical behavior patterns
        0.0 = completely different behavior
        <0.5 = suspiciously different (possible hijacking)
        """
        # Compare tool distributions (cosine similarity)
        tool_sim = _cosine_similarity(self.tool_distribution, other.tool_distribution)

        # Compare temporal patterns
        hour_overlap = len(set(self.active_hours) & set(other.active_hours))
        hour_total = max(len(set(self.active_hours) | set(other.active_hours)), 1)
        temporal_sim = hour_overlap / hour_total

        # Compare parameter characteristics
        param_diff = abs(self.avg_param_entropy - other.avg_param_entropy) / max(self.avg_param_entropy, other.avg_param_entropy, 1)
        param_sim = 1.0 - min(param_diff, 1.0)

        # Weighted combination
        return 0.5 * tool_sim + 0.3 * temporal_sim + 0.2 * param_sim


class FingerprintBuilder:
    """Builds fingerprints incrementally from agent actions."""

    def __init__(self):
        self._fingerprints: dict[str, AgentFingerprint] = {}
        self._tool_counts: dict[str, Counter] = {}
        self._hour_counts: dict[str, Counter] = {}
        self._transitions: dict[str, Counter] = {}
        self._last_tool: dict[str, str] = {}
        self._param_lengths: dict[str, list] = {}
        self._param_entropies: dict[str, list] = {}

    def observe(self, action: AgentAction) -> None:
        """Process an action and update the agent's fingerprint."""
        agent_id = action.agent_id

        if agent_id not in self._tool_counts:
            self._tool_counts[agent_id] = Counter()
            self._hour_counts[agent_id] = Counter()
            self._transitions[agent_id] = Counter()
            self._param_lengths[agent_id] = []
            self._param_entropies[agent_id] = []

        # Track tool usage
        self._tool_counts[agent_id][action.tool_name] += 1

        # Track active hours
        self._hour_counts[agent_id][action.timestamp.hour] += 1

        # Track transitions
        if agent_id in self._last_tool:
            transition = (self._last_tool[agent_id], action.tool_name)
            self._transitions[agent_id][transition] += 1
        self._last_tool[agent_id] = action.tool_name

        # Track parameter characteristics
        params_str = str(action.parameters)
        self._param_lengths[agent_id].append(len(params_str))
        self._param_entropies[agent_id].append(_entropy(params_str))

    def get_fingerprint(self, agent_id: str) -> AgentFingerprint | None:
        """Get the current fingerprint for an agent."""
        if agent_id not in self._tool_counts:
            return None

        total_actions = sum(self._tool_counts[agent_id].values())
        if total_actions < 10:
            return None  # Not enough data for meaningful fingerprint

        # Build fingerprint
        fp = AgentFingerprint(agent_id=agent_id, observation_count=total_actions)

        # Tool distribution (normalized)
        fp.tool_distribution = {
            tool: count / total_actions
            for tool, count in self._tool_counts[agent_id].items()
        }

        # Active hours (hours with >5% of activity)
        hour_total = sum(self._hour_counts[agent_id].values())
        fp.active_hours = [
            h for h, c in self._hour_counts[agent_id].items()
            if c / hour_total > 0.05
        ]

        # Parameter averages
        if self._param_lengths[agent_id]:
            fp.avg_param_length = sum(self._param_lengths[agent_id]) / len(self._param_lengths[agent_id])
        if self._param_entropies[agent_id]:
            fp.avg_param_entropy = sum(self._param_entropies[agent_id]) / len(self._param_entropies[agent_id])

        # Top transitions
        top = self._transitions[agent_id].most_common(5)
        trans_total = sum(self._transitions[agent_id].values()) or 1
        fp.common_transitions = [
            (t[0][0], t[0][1], t[1] / trans_total) for t in top
        ]

        return fp

    def detect_identity_anomaly(self, agent_id: str, reference_fp: AgentFingerprint) -> float:
        """Check if current behavior matches the reference fingerprint.

        Returns: anomaly score 0-99 (high = behavior doesn't match fingerprint)
        """
        current_fp = self.get_fingerprint(agent_id)
        if current_fp is None:
            return 0  # Not enough data

        similarity = current_fp.similarity(reference_fp)

        # Convert similarity to anomaly score (inverted)
        # similarity 1.0 = anomaly 0, similarity 0.0 = anomaly 99
        anomaly = int((1.0 - similarity) * 99)
        return anomaly


def _cosine_similarity(dict_a: dict[str, float], dict_b: dict[str, float]) -> float:
    """Compute cosine similarity between two frequency distributions."""
    all_keys = set(dict_a.keys()) | set(dict_b.keys())
    if not all_keys:
        return 1.0

    dot_product = sum(dict_a.get(k, 0) * dict_b.get(k, 0) for k in all_keys)
    magnitude_a = math.sqrt(sum(v**2 for v in dict_a.values())) or 1
    magnitude_b = math.sqrt(sum(v**2 for v in dict_b.values())) or 1

    return dot_product / (magnitude_a * magnitude_b)


def _entropy(text: str) -> float:
    """Shannon entropy."""
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((c/length) * math.log2(c/length) for c in counts.values())
