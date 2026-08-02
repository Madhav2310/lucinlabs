"""Peer-Group Comparison Model — compare agent to its cohort.

Detects anomalies by comparing an agent's behavior not just to its
own history, but to OTHER agents of the same type. If 99 support
agents call lookup_customer as their most common tool, but one
agent suddenly uses execute_shell most frequently — that's anomalous
relative to the PEER GROUP even if it's within its own baseline.

This is the "compared to what?" dimension of anomaly detection.
Same principle as: if one cardholder suddenly spends 10x more than
others in the same demographic, that's suspicious even if they've
had high spending before.

Architecture:
- Agents are grouped by type/role (support, coding, data, research)
- Aggregate statistics computed per group
- Individual agents scored against their group's distribution
- Outlier detection identifies agents deviating from peers
"""

from dataclasses import dataclass, field
from collections import Counter, defaultdict
import math


@dataclass
class PeerGroupStats:
    """Aggregate statistics for a group of similar agents."""
    group_name: str
    agent_count: int = 0
    total_observations: int = 0

    # Aggregate tool distribution across all agents in group
    tool_distribution: dict[str, float] = field(default_factory=dict)

    # Timing stats
    avg_actions_per_hour: float = 0.0
    std_actions_per_hour: float = 0.0

    # Parameter stats
    avg_param_entropy: float = 0.0


class PeerComparisonModel:
    """Compares individual agents against their peer group.

    Groups agents by a configurable criterion (framework, role, tool set similarity)
    and detects agents whose behavior deviates significantly from their peers.
    """

    def __init__(self):
        self._groups: dict[str, PeerGroupStats] = {}
        self._agent_groups: dict[str, str] = {}  # agent_id -> group_name
        self._agent_tool_counts: dict[str, Counter] = defaultdict(Counter)
        self._agent_action_counts: dict[str, int] = defaultdict(int)

    def assign_group(self, agent_id: str, group_name: str) -> None:
        """Assign an agent to a peer group.

        Groups could be: "support_agents", "coding_agents", "data_agents"
        Or auto-assigned based on tool similarity.
        """
        self._agent_groups[agent_id] = group_name
        if group_name not in self._groups:
            self._groups[group_name] = PeerGroupStats(group_name=group_name)

    def observe(self, agent_id: str, tool_name: str) -> None:
        """Record an observation for peer comparison."""
        self._agent_tool_counts[agent_id][tool_name] += 1
        self._agent_action_counts[agent_id] += 1

        # Update group stats
        group_name = self._agent_groups.get(agent_id)
        if group_name and group_name in self._groups:
            group = self._groups[group_name]
            group.total_observations += 1

    def compute_peer_anomaly(self, agent_id: str) -> tuple[int, list[str]]:
        """Score how much an agent deviates from its peer group.

        Returns:
            (anomaly_score 0-99, list of contributing factors)
        """
        group_name = self._agent_groups.get(agent_id)
        if not group_name:
            return 0, ["No peer group assigned"]

        # Get peer agents (same group, excluding self)
        peer_agents = [
            aid for aid, gname in self._agent_groups.items()
            if gname == group_name and aid != agent_id
        ]

        if len(peer_agents) < 2:
            return 0, ["Insufficient peers for comparison (need 3+)"]

        score = 0
        factors = []

        # Compare tool distribution to peer average
        agent_dist = self._get_tool_distribution(agent_id)
        peer_dist = self._get_peer_average_distribution(peer_agents)

        if agent_dist and peer_dist:
            # Find tools used by this agent but NOT by peers
            agent_unique_tools = set(agent_dist.keys()) - set(peer_dist.keys())
            if agent_unique_tools:
                score += 30
                factors.append(f"Uses tools no peer uses: {list(agent_unique_tools)[:3]}")

            # Find tools heavily used by peers but not this agent
            peer_common = [t for t, f in peer_dist.items() if f > 0.2]
            agent_missing = [t for t in peer_common if agent_dist.get(t, 0) < 0.05]
            if agent_missing:
                score += 20
                factors.append(f"Missing common peer tools: {agent_missing[:3]}")

            # Cosine distance from peer average
            cos_sim = _cosine_similarity(agent_dist, peer_dist)
            if cos_sim < 0.5:
                score += 40
                factors.append(f"Low similarity to peer group (cosine: {cos_sim:.2f})")
            elif cos_sim < 0.7:
                score += 20
                factors.append(f"Moderate deviation from peers (cosine: {cos_sim:.2f})")

        return min(99, score), factors

    def _get_tool_distribution(self, agent_id: str) -> dict[str, float]:
        """Get normalized tool distribution for an agent."""
        counts = self._agent_tool_counts.get(agent_id)
        if not counts:
            return {}
        total = sum(counts.values())
        return {tool: count/total for tool, count in counts.items()}

    def _get_peer_average_distribution(self, peer_ids: list[str]) -> dict[str, float]:
        """Compute average tool distribution across peer agents."""
        all_tools: dict[str, float] = defaultdict(float)
        valid_peers = 0

        for pid in peer_ids:
            dist = self._get_tool_distribution(pid)
            if dist:
                valid_peers += 1
                for tool, freq in dist.items():
                    all_tools[tool] += freq

        if valid_peers == 0:
            return {}

        return {tool: total/valid_peers for tool, total in all_tools.items()}


def _cosine_similarity(dict_a: dict[str, float], dict_b: dict[str, float]) -> float:
    """Cosine similarity between two distributions."""
    all_keys = set(dict_a.keys()) | set(dict_b.keys())
    if not all_keys:
        return 1.0
    dot = sum(dict_a.get(k, 0) * dict_b.get(k, 0) for k in all_keys)
    mag_a = math.sqrt(sum(v**2 for v in dict_a.values())) or 1
    mag_b = math.sqrt(sum(v**2 for v in dict_b.values())) or 1
    return dot / (mag_a * mag_b)
