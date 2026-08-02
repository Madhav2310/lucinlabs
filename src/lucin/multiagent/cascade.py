"""Cascading failure detection across multi-agent graphs.

Blueprint §6.4: "Monitor cascading-failure (ASI08) and worm R₀ across the
cluster graph."

Reference: Morris II (arXiv:2403.02817) — the first demonstrated multi-agent
worm. R₀ > 1 means the worm spreads. We track the effective reproduction
number from the agent graph's topology and observed failure propagation.

A "failure" is any of:
  - An agent being compromised (confirmed prompt injection)
  - An agent producing anomalous output (behavioral monitor alert)
  - An agent calling a tool it shouldn't (capability scope violation)

Usage:
    graph = AgentGraph()
    graph.add_agent("triage",  delegates_to=["sales", "refunds"])
    graph.add_agent("sales",   delegates_to=["email_sender"])
    graph.add_agent("refunds", delegates_to=["payment_processor"])

    detector = CascadeDetector(graph)
    report = detector.propagate_failure("triage")
    print(report.r_zero)              # effective reproduction number
    print(report.blast_radius)        # set of agents that would be affected
    print(report.highest_risk_paths)  # paths with most dangerous tools
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from lucin.aifg import TrifectaFinding


# Tool-name substrings that mark an agent as holding a dangerous (egress /
# code-exec / write) capability — the sink side of a cross-agent trifecta.
_DANGEROUS_TOOL_MARKERS = frozenset({
    "exec", "shell", "bash", "subprocess", "code_interpreter",
    "send_email", "send_slack", "http_post", "write_file",
    "payment_processor", "database_write", "deploy",
})


@dataclass
class AgentNode:
    """One agent in the multi-agent graph."""
    agent_id:     str
    role:         str = ""
    tools:        list[str] = field(default_factory=list)
    delegates_to: list[str] = field(default_factory=list)
    trust_level:  str = "untrusted"  # "trusted", "untrusted", "isolated"

    @property
    def dangerous_tools(self) -> list[str]:
        """The agent's tools that match a dangerous-capability marker."""
        return [t for t in self.tools
                if any(d in t.lower() for d in _DANGEROUS_TOOL_MARKERS)]

    @property
    def is_high_privilege(self) -> bool:
        """True if this agent has high-privilege tools."""
        return bool(self.dangerous_tools)


class AgentGraph:
    """Directed graph of agent delegation relationships.

    An edge A → B means "Agent A can delegate tasks to Agent B."
    This is the topology over which failures propagate.
    """

    def __init__(self):
        self._nodes: dict[str, AgentNode] = {}

    def add_agent(self, agent_id: str,
                  role: str = "",
                  tools: list[str] | None = None,
                  delegates_to: list[str] | None = None,
                  trust_level: str = "untrusted") -> "AgentGraph":
        self._nodes[agent_id] = AgentNode(
            agent_id=agent_id,
            role=role,
            tools=tools or [],
            delegates_to=delegates_to or [],
            trust_level=trust_level,
        )
        return self

    def get(self, agent_id: str) -> AgentNode | None:
        return self._nodes.get(agent_id)

    def successors(self, agent_id: str) -> list[str]:
        """Agents that `agent_id` can delegate to (direct successors)."""
        node = self._nodes.get(agent_id)
        return node.delegates_to if node else []

    def all_agents(self) -> list[str]:
        return list(self._nodes.keys())

    def to_aifg(self):
        """Project this delegation graph into an `lucin.aifg.AIFG`.

        Part of the "one coherent AIFG model" coherence contract
        (tests/test_aifg_coherence.py): the multi-agent graph must reconstruct
        into the SAME `AIFG` dataclass / `to_dict()` schema as SCAN and the
        runtime provenance graph — not a fourth parallel type.

        HONEST SCOPE: this is a COARSER, agent-granularity projection than the
        tool-granularity SCAN/GUARD graphs. Nodes are AGENTS (not individual
        tools); a delegation edge A->B becomes both a DATA and a CONTROL edge
        (A can pass data to and trigger B). trust_level maps to integrity;
        an agent holding a dangerous tool (`is_high_privilege`) is an egress
        sink. It shares the AIFG *type and schema* and runs `query_trifecta`
        unchanged; it does NOT claim tool-level dataflow precision.
        """
        from lucin.aifg import (
            AIFG, AIFGNode, AIFGEdge, EdgeKind, IFCLabel,
            Integrity, Confidentiality,
        )

        g = AIFG(agent_name="multiagent-cluster")
        for aid, node in self._nodes.items():
            integ = (Integrity.TRUSTED if node.trust_level == "trusted"
                     else Integrity.UNTRUSTED)
            # An agent delegating in from untrusted input is a source of
            # untrusted data; a high-privilege agent is an egress sink.
            is_egress = node.is_high_privilege
            g.nodes[aid] = AIFGNode(
                node_id=aid,
                label=IFCLabel(integrity=integ,
                               confidentiality=Confidentiality.INTERNAL),
                is_source=True,          # every agent can originate/forward data
                is_sink=is_egress,
                is_egress=is_egress,
            )
        for aid, node in self._nodes.items():
            for target in node.delegates_to:
                if target in g.nodes:
                    g.edges.append(AIFGEdge(aid, target, EdgeKind.DATA))
                    g.edges.append(AIFGEdge(aid, target, EdgeKind.CONTROL))
        return g


@dataclass
class CascadeReport:
    """Result of a cascade analysis from a failure source.

    Attributes:
        source_agent:    Agent where the failure originates.
        blast_radius:    Set of ALL agents reachable from the source.
        high_risk_agents: Agents in the blast radius with dangerous tools.
        r_zero:          Effective reproduction number (avg successors in
                         blast radius for agents with dangerous tools).
                         R₀ > 1 = worm-spreads-category risk.
        propagation_tree: BFS tree of how failure propagates.
        depth:           Max depth of the propagation tree.
        highest_risk_paths: The paths with the most high-privilege agents.
    """
    source_agent:      str
    blast_radius:      set[str]
    high_risk_agents:  list[str]
    r_zero:            float
    propagation_tree:  dict[str, list[str]]  # parent → children
    depth:             int
    highest_risk_paths: list[list[str]]

    @property
    def is_worm_risk(self) -> bool:
        """R₀ > 1 means the failure self-amplifies (worm territory)."""
        return self.r_zero > 1.0

    def describe(self) -> str:
        lines = [
            f"Cascade Analysis: {self.source_agent}",
            f"  Blast radius:   {len(self.blast_radius)} agents: {sorted(self.blast_radius)}",
            f"  High-risk in blast: {self.high_risk_agents}",
            f"  R₀ = {self.r_zero:.2f} ({'WORM RISK' if self.is_worm_risk else 'contained'})",
            f"  Max depth: {self.depth}",
        ]
        if self.highest_risk_paths:
            lines.append("  Highest-risk paths:")
            for path in self.highest_risk_paths[:3]:
                lines.append(f"    {' → '.join(path)}")
        return "\n".join(lines)


class CascadeDetector:
    """Detects cascading failure potential in a multi-agent graph.

    Implements:
      1. BFS blast-radius computation (which agents are reachable from source)
      2. R₀ estimation (effective reproduction number in the graph)
      3. High-risk path identification (paths through dangerous-tool agents)

    Reference for R₀ analogy: Morris II (arXiv:2403.02817) showed that
    multi-agent systems exhibit worm-like propagation when R₀ > 1.
    """

    def __init__(self, graph: AgentGraph):
        self.graph = graph

    def propagate_failure(self, source_agent: str) -> CascadeReport:
        """Compute the full cascade from source_agent failing.

        Uses BFS to find all reachable agents and builds the propagation tree.
        """
        visited: set[str] = set()
        parent: dict[str, str] = {source_agent: ""}
        tree: dict[str, list[str]] = {}
        depths: dict[str, int] = {source_agent: 0}
        queue = deque([source_agent])

        while queue:
            current = queue.popleft()
            if current in visited:
                continue
            visited.add(current)
            tree[current] = []

            for succ in self.graph.successors(current):
                if succ not in visited:
                    tree[current].append(succ)
                    parent[succ] = current
                    depths[succ] = depths[current] + 1
                    queue.append(succ)

        blast_radius = visited - {source_agent}
        max_depth = max(depths.values()) if depths else 0

        # High-risk agents: in blast radius AND have dangerous tools
        high_risk = [
            a for a in blast_radius
            if (node := self.graph.get(a)) and node.is_high_privilege
        ]

        # R₀: avg number of successors for high-privilege agents in blast radius
        # (this is the "reproduction number" — how many agents each compromised
        # high-risk agent can further spread to)
        if high_risk:
            successors_counts = [
                len(self.graph.successors(a)) for a in high_risk
            ]
            r_zero = sum(successors_counts) / len(successors_counts)
        else:
            # Use all agents in blast radius for a baseline R₀
            all_succ = [len(self.graph.successors(a)) for a in blast_radius]
            r_zero = sum(all_succ) / max(len(all_succ), 1)

        # Find highest-risk paths (DFS, prefer paths through high-risk agents)
        paths = self._find_paths(source_agent, max_paths=5)
        risk_paths = sorted(
            paths,
            key=lambda p: sum(1 for a in p if a in high_risk),
            reverse=True,
        )

        return CascadeReport(
            source_agent=source_agent,
            blast_radius=blast_radius,
            high_risk_agents=high_risk,
            r_zero=r_zero,
            propagation_tree=tree,
            depth=max_depth,
            highest_risk_paths=risk_paths[:3],
        )

    def _find_paths(self, source: str, max_paths: int = 5,
                    max_depth: int = 10) -> list[list[str]]:
        """DFS to find distinct paths from source (up to max_paths)."""
        paths = []
        stack = [([source], {source})]

        while stack and len(paths) < max_paths:
            path, visited = stack.pop()
            current = path[-1]
            succs = [s for s in self.graph.successors(current)
                     if s not in visited]

            if not succs or len(path) >= max_depth:
                if len(path) > 1:
                    paths.append(path)
                continue

            for succ in succs:
                stack.append((path + [succ], visited | {succ}))

        return paths

    def cross_agent_trifecta(self) -> list["CrossAgentTrifecta"]:
        """Convenience: cross-agent lethal-trifecta findings for this graph."""
        return query_cross_agent_trifecta(self.graph)

    def compute_global_r_zero(self) -> float:
        """Compute the global effective reproduction number for the graph.

        R₀ = average out-degree of all agents (weighted by privilege level).
        R₀ > 1 → any injected failure will spread on average.
        """
        agents = self.graph.all_agents()
        if not agents:
            return 0.0

        # Weight high-privilege agents more (their failures spread further)
        total_weighted = 0.0
        total_weight = 0.0
        for a in agents:
            node = self.graph.get(a)
            if node is None:
                continue
            w = 2.0 if node.is_high_privilege else 1.0
            out = len(node.delegates_to)
            total_weighted += w * out
            total_weight += w

        return total_weighted / max(total_weight, 1.0)


# ---------------------------------------------------------------------------
# Cross-agent lethal trifecta (breadth): an untrusted source in agent A reaching
# a dangerous sink in agent B via a delegation / handoff edge.
# ---------------------------------------------------------------------------

@dataclass
class CrossAgentTrifecta:
    """A lethal trifecta whose flow CROSSES an agent boundary.

    An untrusted origin agent (`source_agent`) can steer — over one or more
    delegation/handoff edges — a high-privilege agent (`sink_agent`) that holds
    a dangerous (egress / code-exec / write) tool, while data also flows along
    that same handoff chain. This is the multi-agent analogue of the single-file
    lethal trifecta (aifg.query_trifecta) and OWASP ASI08 (Data Exfiltration) /
    the Morris-II worm handoff pattern.

    Reuses the SAME AIFG type and `query_trifecta` query, run over the merged
    multi-agent graph produced by `AgentGraph.to_aifg()` — one coherent model,
    agent-granular (see AgentGraph.to_aifg's honest-scope docstring).
    """
    source_agent:    str          # untrusted origin (can steer the sink)
    sink_agent:      str          # high-privilege agent holding the dangerous tool
    handoff_path:    list[str]    # delegation chain source_agent -> ... -> sink_agent
    dangerous_tools: list[str]    # sink_agent's dangerous tools
    finding:         "TrifectaFinding"   # the underlying AIFG finding (shared type)

    def describe(self) -> str:
        chain = " → ".join(self.handoff_path)
        tools = ", ".join(self.dangerous_tools) or "(unknown)"
        return (
            f"Cross-agent exfiltration: untrusted '{self.source_agent}' can "
            f"steer high-privilege '{self.sink_agent}' [{tools}]\n"
            f"  Handoff path: {chain}"
        )


def query_cross_agent_trifecta(graph: "AgentGraph") -> list[CrossAgentTrifecta]:
    """Find cross-agent lethal-trifecta flows in a multi-agent delegation graph.

    Projects `graph` into the shared `lucin.aifg.AIFG` via
    `AgentGraph.to_aifg()` and runs the SAME `query_trifecta` reachability
    query. A finding is CROSS-AGENT iff an UNTRUSTED agent can steer the egress
    sink over a real delegation/handoff path to a DIFFERENT agent — i.e. the
    trifecta is only realisable because one agent hands off to another.
    (Single-agent, self-contained trifectas are handled by SCAN on that agent's
    own code and are excluded here.)

    For each sink we report the FARTHEST-upstream untrusted origin (the root of
    the handoff chain, deterministic: longest path, then lexicographic), so the
    handoff_path is the most complete attacker chain rather than an arbitrary
    intermediate delegator.
    """
    from lucin.aifg import query_trifecta, EdgeKind, _shortest_path

    g = graph.to_aifg()
    findings_by_sink = {tf.egress_sink: tf for tf in query_trifecta(g)}

    out: list[CrossAgentTrifecta] = []
    for sink in sorted(findings_by_sink):
        # every untrusted agent that can steer `sink` over a delegation chain
        origins: list[tuple[str, list[str]]] = []
        for aid, node in g.nodes.items():
            if aid == sink or not node.label.is_untrusted():
                continue
            path = _shortest_path(g, aid, sink, EdgeKind.CONTROL)
            if path and len(path) >= 2:
                origins.append((aid, path))
        if not origins:
            continue   # sink steerable only by itself → not cross-agent
        # deterministic: root origin = longest handoff chain, tie-break by name
        origins.sort(key=lambda ap: (-len(ap[1]), ap[0]))
        origin, path = origins[0]
        sink_node = graph.get(sink)
        out.append(CrossAgentTrifecta(
            source_agent=origin,
            sink_agent=sink,
            handoff_path=path,
            dangerous_tools=(sink_node.dangerous_tools if sink_node else []),
            finding=findings_by_sink[sink],
        ))
    return out
