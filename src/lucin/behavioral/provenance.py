"""Provenance Tracking — causal graph of agent actions.

Tracks which action CAUSED which, enabling:
1. Root cause analysis (which tool call led to the data leak?)
2. Blast radius calculation (if this action was malicious, what did it affect?)
3. Anomaly context (this action is unusual BECAUSE it was triggered by an unusual predecessor)

Reference: TraceAegis (arXiv:2510.11203) — hierarchical provenance for agent monitoring

The provenance graph structure:
- Nodes = individual agent actions (tool calls, responses, decisions)
- Edges = causal relationships (action A triggered action B)
- Metadata = timing, user, context, outcome

This extends our behavioral scoring by adding causal context.
Instead of scoring each action independently, we score the CHAIN.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class ProvenanceNode:
    """A single action in the provenance graph."""
    id: str
    action_type: str  # "tool_call", "llm_response", "user_input", "system_event"
    tool_name: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    parameters: dict = field(default_factory=dict)
    result_summary: str = ""
    triggered_by: str | None = None  # ID of the causing action
    metadata: dict = field(default_factory=dict)


@dataclass
class ProvenanceGraph:
    """Causal graph of agent actions for a session."""
    session_id: str
    agent_name: str
    nodes: dict[str, ProvenanceNode] = field(default_factory=dict)
    _action_counter: int = 0

    def record_action(
        self,
        action_type: str,
        tool_name: str = "",
        parameters: dict | None = None,
        result_summary: str = "",
        triggered_by: str | None = None,
    ) -> str:
        """Record a new action and return its ID."""
        self._action_counter += 1
        node_id = f"{self.session_id}-{self._action_counter:04d}"

        node = ProvenanceNode(
            id=node_id,
            action_type=action_type,
            tool_name=tool_name,
            parameters=parameters or {},
            result_summary=result_summary,
            triggered_by=triggered_by,
        )
        self.nodes[node_id] = node
        return node_id

    def get_causal_chain(self, node_id: str) -> list[ProvenanceNode]:
        """Get the full causal chain leading to a specific action.

        Traces back through triggered_by links to find the root cause.
        """
        chain = []
        current_id = node_id
        visited = set()

        while current_id and current_id not in visited:
            visited.add(current_id)
            node = self.nodes.get(current_id)
            if not node:
                break
            chain.append(node)
            current_id = node.triggered_by

        return list(reversed(chain))  # Root cause first

    def get_blast_radius(self, node_id: str) -> list[ProvenanceNode]:
        """Get all actions that were triggered (directly or indirectly) by a node.

        If action A was malicious, what else did it cause?
        """
        affected = []
        queue = [node_id]
        visited = set()

        while queue:
            current = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)

            # Find all nodes triggered by this one
            for nid, node in self.nodes.items():
                if node.triggered_by == current and nid not in visited:
                    affected.append(node)
                    queue.append(nid)

        return affected

    def get_anomalous_chains(self, max_depth: int = 5) -> list[list[ProvenanceNode]]:
        """Find action chains that are unusually long or contain unusual transitions.

        Long causal chains (depth > max_depth) may indicate:
        - Runaway agent behavior
        - Cascading failures
        - Multi-step attacks
        """
        anomalous = []
        for node_id in self.nodes:
            chain = self.get_causal_chain(node_id)
            if len(chain) > max_depth:
                anomalous.append(chain)
        return anomalous

    @property
    def action_count(self) -> int:
        return len(self.nodes)

    @property
    def max_chain_depth(self) -> int:
        """Deepest causal chain in the graph."""
        if not self.nodes:
            return 0
        return max(len(self.get_causal_chain(nid)) for nid in self.nodes)
