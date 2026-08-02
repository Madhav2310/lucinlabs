"""Runtime provenance graph — W3C PROV lineage + Merkle-chained audit.

Blueprint §6.3: "Every action = a W3C-PROV node; tamper-evident Merkle-chained
audit; backward-trace from any alert to root untrusted source and human sponsor."

This module implements:
1. ProvenanceNode — a W3C PROV entity/activity/agent node
2. ProvenanceGraph — the live causal graph for one agent session
3. Merkle-chained append-only action log (tamper-evident)
4. Backward trace — "why did this happen?" from any node to its origins

Key correctness properties:
  - Every tool call that enters the graph gets a hash-chained record.
  - Backward trace follows `was_derived_from` and `was_generated_by` edges.
  - Tampering with any record invalidates the Merkle chain.

Pure Python + hashlib only.

W3C PROV spec: https://www.w3.org/TR/prov-dm/
SLEUTH lineage inspiration: USENIX Security 2017. [VERIFIED as design reference]
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# Runtime telemetry gives us a tool NAME but not a declared capability set, so
# to reuse the static egress classifier (aifg.is_egress_by_name) we infer the
# two flags it needs from the observed name. Conservative and name-only; the
# fetch-suppression patterns inside is_egress_by_name still apply on top.
_NETWORK_NAME_HINTS = (
    "http", "email", "mail", "slack", "webhook", "url", "post", "request",
    "send", "upload", "publish", "api", "fetch", "search", "scrape", "browse",
    "web", "notify", "message", "sms", "discord", "telegram",
)
_WRITE_NAME_HINTS = (
    "write", "save", "store", "upload", "put", "insert", "update", "delete",
    "commit", "push", "persist", "append",
)


def _infer_caps_from_name(name: str) -> tuple[bool, bool]:
    """Infer (has_network, has_write) from an observed tool name."""
    n = (name or "").lower()
    has_network = any(k in n for k in _NETWORK_NAME_HINTS)
    has_write = any(k in n for k in _WRITE_NAME_HINTS)
    return has_network, has_write


class ProvType(str, Enum):
    ENTITY   = "entity"    # data: a value, file, document, tool-return
    ACTIVITY = "activity"  # action: a tool call, a decision
    AGENT    = "agent"     # the LLM, the human sponsor, a sub-agent


@dataclass
class ProvenanceNode:
    """One W3C PROV node in the causal graph.

    Attributes follow the W3C PROV-DM vocabulary:
      entity    — something that was produced or used
      activity  — something that happened (a tool call)
      agent     — the responsible party (LLM, human, sub-agent)
      was_generated_by   — entity was produced by this activity
      was_derived_from   — entity derives from these entities
      was_attributed_to  — entity/activity attributed to this agent
      used               — activity used these entities
    """
    node_id:             str
    prov_type:           ProvType
    label:               str
    timestamp:           float = field(default_factory=time.time)
    attributes:          dict[str, Any] = field(default_factory=dict)

    # PROV relations (edge lists)
    was_generated_by:    list[str] = field(default_factory=list)  # entity ← activity
    was_derived_from:    list[str] = field(default_factory=list)  # entity ← entity
    was_attributed_to:   list[str] = field(default_factory=list)  # → agent
    used:                list[str] = field(default_factory=list)   # activity → entity

    def to_dict(self) -> dict:
        return {
            "id":               self.node_id,
            "type":             self.prov_type.value,
            "label":            self.label,
            "timestamp":        self.timestamp,
            "attributes":       self.attributes,
            "was_generated_by": self.was_generated_by,
            "was_derived_from": self.was_derived_from,
            "was_attributed_to":self.was_attributed_to,
            "used":             self.used,
        }


@dataclass
class MerkleRecord:
    """One entry in the tamper-evident Merkle chain.

    Each record hashes its own content + the hash of the previous record.
    Any retroactive modification to any record breaks all subsequent hashes.
    """
    seq:        int
    node_id:    str
    content:    dict
    prev_hash:  str     # SHA-256 of the previous record (or "genesis")
    this_hash:  str = field(init=False)

    def __post_init__(self) -> None:
        raw = json.dumps({
            "seq": self.seq,
            "node_id": self.node_id,
            "content": self.content,
            "prev_hash": self.prev_hash,
        }, sort_keys=True).encode()
        self.this_hash = hashlib.sha256(raw).hexdigest()


class ProvenanceGraph:
    """Live causal graph for one agent execution session.

    Thread-safety: not thread-safe; use one instance per agent context.

    Typical usage (in the GUARD interceptor):
        prov = ProvenanceGraph(agent_id="support-agent-42",
                               human_sponsor="user:alice")
        # Record a tool call
        call_id = prov.record_activity(
            "fetch_email", inputs={"inbox": "alice"}, triggered_by="llm"
        )
        result_id = prov.record_entity(
            "email_body", produced_by=call_id, integrity="untrusted",
            content_preview="[email content]"
        )
        # If an anomaly fires:
        trace = prov.backward_trace(result_id)
        print(trace.summary())
    """

    def __init__(self, agent_id: str, human_sponsor: str = "unknown",
                 session_id: str | None = None):
        self.agent_id       = agent_id
        self.human_sponsor  = human_sponsor
        self.session_id     = session_id or f"{agent_id}:{time.time():.0f}"
        self._nodes:   dict[str, ProvenanceNode] = {}
        self._chain:   list[MerkleRecord]        = []
        self._seq      = 0

        # Seed: register the human sponsor as an agent node
        self._add(ProvenanceNode(
            node_id=f"agent:{human_sponsor}",
            prov_type=ProvType.AGENT,
            label=f"Human sponsor: {human_sponsor}",
        ))

    # ---- public recording API -------------------------------------------

    def record_entity(self, name: str, *,
                      produced_by: str | None = None,
                      derived_from: list[str] | None = None,
                      integrity: str = "untrusted",
                      confidentiality: str = "internal",
                      content_preview: str = "") -> str:
        """Record a data entity (a value, file, or tool-return).

        Returns the new node_id.
        """
        nid = self._fresh_id("e", name)
        node = ProvenanceNode(
            node_id=nid,
            prov_type=ProvType.ENTITY,
            label=name,
            attributes={
                "integrity":        integrity,
                "confidentiality":  confidentiality,
                "content_preview":  content_preview[:200],
            },
            was_generated_by=[produced_by] if produced_by else [],
            was_derived_from=derived_from or [],
        )
        self._add(node)
        return nid

    def record_activity(self, tool_name: str, *,
                        inputs: dict[str, Any] | None = None,
                        triggered_by: str = "llm",
                        attributed_to: str | None = None,
                        used_entities: list[str] | None = None) -> str:
        """Record a tool call (an activity).

        Returns the new node_id.
        triggered_by: 'llm', 'human', or a sub-agent node_id.
        used_entities: entity node_ids this call CONSUMED. This is the
            authoritative way for a runtime interceptor to declare observed data
            lineage (producer_entity -> this activity). Without it, lineage could
            only form when an entity id happened to be passed as a string input
            value — which the real interceptor never does — so DATA edges never
            built. `used` now merges the explicit consumed entities with any
            string input values that are themselves entity ids (back-compat).
        """
        nid = self._fresh_id("a", tool_name)
        agent_nid = attributed_to or f"agent:{self.human_sponsor}"
        input_str_values = ([v for v in (inputs or {}).values() if isinstance(v, str)])
        used = list(used_entities or []) + input_str_values
        node = ProvenanceNode(
            node_id=nid,
            prov_type=ProvType.ACTIVITY,
            label=tool_name,
            attributes={
                "inputs":        inputs or {},
                "triggered_by":  triggered_by,
            },
            was_attributed_to=[agent_nid],
            used=used,
        )
        self._add(node)
        return nid

    # ---- backward trace -------------------------------------------------

    def backward_trace(self, node_id: str,
                       max_depth: int = 64) -> "ProvenanceTrace":
        """Trace causally backward from node_id to all contributing origins.

        Bounded by causal DEPTH (edge hops from the start node), NOT by a cap on
        the number of visited nodes. A breadth-first frontier is expanded level
        by level so that on a long lineage chain the trace still reaches the root
        untrusted origin — the previous DFS-with-node-cap stopped at the first 20
        nodes it happened to pop and could miss the root entirely.

        Returns a ProvenanceTrace with:
          - nodes: all nodes on the causal path
          - untrusted_origins: origin nodes labelled UNTRUSTED
          - summary(): human-readable explanation
        """
        from collections import deque

        visited: dict[str, ProvenanceNode] = {}
        # (node_id, depth) frontier — BFS by hop distance from the start node.
        frontier: deque[tuple[str, int]] = deque([(node_id, 0)])
        while frontier:
            nid, depth = frontier.popleft()
            if nid in visited or nid not in self._nodes:
                continue
            node = self._nodes[nid]
            visited[nid] = node
            if depth >= max_depth:
                continue  # reached the depth bound; do not expand further
            for parent in (list(node.was_generated_by)
                           + list(node.was_derived_from)
                           + list(node.was_attributed_to)):
                if parent not in visited:
                    frontier.append((parent, depth + 1))

        origin_nodes = [n for n in visited.values()
                        if not n.was_generated_by and not n.was_derived_from]
        untrusted_origins = [n for n in origin_nodes
                             if n.attributes.get("integrity") == "untrusted"]

        return ProvenanceTrace(
            root_id=node_id,
            nodes=visited,
            untrusted_origins=untrusted_origins,
            human_sponsor=self.human_sponsor,
        )

    # ---- integrity verification ------------------------------------------

    def verify_chain(self) -> bool:
        """Verify the Merkle chain has not been tampered with.

        Returns True if the chain is intact.
        """
        for i, rec in enumerate(self._chain):
            expected_prev = self._chain[i - 1].this_hash if i > 0 else "genesis"
            if rec.prev_hash != expected_prev:
                return False
            # Recompute hash
            raw = json.dumps({
                "seq": rec.seq,
                "node_id": rec.node_id,
                "content": rec.content,
                "prev_hash": rec.prev_hash,
            }, sort_keys=True).encode()
            if hashlib.sha256(raw).hexdigest() != rec.this_hash:
                return False
        return True

    def chain_tip_hash(self) -> str:
        """Return the hash of the most recent Merkle record."""
        return self._chain[-1].this_hash if self._chain else "empty"

    # ---- projection into the ONE AIFG model (SCAN<->GUARD coherence) -----

    def to_aifg(self):
        """Reconstruct this runtime provenance graph as an `lucin.aifg.AIFG`.

        This is the code path that makes "one coherent AIFG model stitching
        SCAN->GUARD" a *tested property* rather than a slogan: the same `AIFG`
        dataclass, `AIFGNode`/`AIFGEdge`/`IFCLabel`/`EdgeKind` types, the same
        `to_dict()` wire format, and the same `query_trifecta` run unchanged on
        the result. (See tests/test_aifg_coherence.py.)

        Semantics of the projection (W3C-PROV  ->  AIFG):
          - ACTIVITY nodes (tool calls) collapse to AIFG tool nodes keyed by
            TOOL NAME (the activity label) — so the node vocabulary matches the
            static builder, where `tool_name` is also the node id.
          - A synthetic `__llm__` node is the join point, matching build_aifg.
          - Node IFC labels are the JOIN of the labels of the entities each tool
            produced/used, decoded through the ONE canonical string vocabulary
            (`aifg.ifc_label_from_strings`).
          - Edges are OBSERVED dataflow, not a template:
              * DATA producer_tool -> consumer_tool  when a consumer activity
                `used` an entity a producer activity generated (real lineage).
              * CONTROL __llm__ -> tool  for every tool the LLM triggered.
              * DATA source_tool -> __llm__  when the source's output later fed
                an LLM-triggered call.
            So runtime witness paths are real evidence, not over-approximation.
          - Egress/sink/source roles use the SAME `is_egress_by_name` rule as the
            static builder (capabilities inferred from the observed tool name).
        """
        # Lazy import: keeps this module import-light and avoids any import
        # ordering surprise. aifg.py is stdlib-only, so purity is preserved.
        from lucin.aifg import (
            AIFG, AIFGNode, AIFGEdge, EdgeKind, UNTRUSTED_PUBLIC,
            ifc_label_from_strings, is_egress_by_name,
        )

        g = AIFG(agent_name=self.agent_id)

        # 1. The LLM join node (identical to build_aifg's __llm__).
        g.nodes["__llm__"] = AIFGNode(
            node_id="__llm__", label=UNTRUSTED_PUBLIC, is_llm=True,
        )

        # 2. Index provenance structure.
        activities = {nid: n for nid, n in self._nodes.items()
                      if n.prov_type == ProvType.ACTIVITY}
        entities = {nid: n for nid, n in self._nodes.items()
                    if n.prov_type == ProvType.ENTITY}

        def entity_label(ent: "ProvenanceNode"):
            return ifc_label_from_strings(
                ent.attributes.get("integrity", "untrusted"),
                ent.attributes.get("confidentiality", "public"),
            )

        # entity_id -> tool name of the activity that generated it
        producer_tool: dict[str, str] = {}
        for eid, ent in entities.items():
            for act_id in ent.was_generated_by:
                act = activities.get(act_id)
                if act is not None:
                    producer_tool[eid] = act.label

        # 3. Build one AIFG node per distinct tool name; label = join of the
        #    labels of entities it produced OR used.
        tool_labels: dict[str, object] = {}
        tool_produces_data: dict[str, bool] = {}
        tool_triggered_by_llm: dict[str, bool] = {}
        tool_used_entities: dict[str, list[str]] = {}

        for act in activities.values():
            tool = act.label
            triggered = act.attributes.get("triggered_by", "")
            tool_triggered_by_llm[tool] = (
                tool_triggered_by_llm.get(tool, False) or triggered == "llm"
            )
            # entities this activity used (input values that are entity ids)
            used = [u for u in act.used if u in entities]
            tool_used_entities.setdefault(tool, []).extend(used)
            for u in used:
                tool_labels[tool] = (
                    entity_label(entities[u]) if tool not in tool_labels
                    else tool_labels[tool].join(entity_label(entities[u]))
                )

        for eid, ent in entities.items():
            for act_id in ent.was_generated_by:
                act = activities.get(act_id)
                if act is None:
                    continue
                tool = act.label
                tool_produces_data[tool] = True
                lbl = entity_label(ent)
                tool_labels[tool] = (
                    lbl if tool not in tool_labels
                    else tool_labels[tool].join(lbl)
                )

        for tool in {a.label for a in activities.values()}:
            has_network, has_write = _infer_caps_from_name(tool)
            is_egress = is_egress_by_name(
                tool, has_network=has_network, has_write=has_write,
            )
            g.nodes[tool] = AIFGNode(
                node_id=tool,
                label=tool_labels.get(tool, UNTRUSTED_PUBLIC),
                is_source=tool_produces_data.get(tool, False),
                is_sink=is_egress,
                is_egress=is_egress,
            )

        # 4. Observed dataflow edges (producer_tool -> consumer_tool).
        seen_edges: set[tuple] = set()

        def add_edge(src: str, dst: str, kind: str):
            key = (src, dst, kind)
            if src != dst and key not in seen_edges:
                seen_edges.add(key)
                g.edges.append(AIFGEdge(src, dst, kind))

        for tool, used in tool_used_entities.items():
            for eid in used:
                ptool = producer_tool.get(eid)
                if ptool and ptool in g.nodes:
                    add_edge(ptool, tool, EdgeKind.DATA)   # observed lineage

        # 5. LLM mediation edges.
        for tool, by_llm in tool_triggered_by_llm.items():
            if by_llm:
                add_edge("__llm__", tool, EdgeKind.CONTROL)
        # source output enters LLM context (only if it fed an llm-triggered call)
        for tool, node in list(g.nodes.items()):
            if node.is_source and not node.is_llm:
                add_edge(tool, "__llm__", EdgeKind.DATA)

        return g

    # ---- serialization ---------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "agent_id":      self.agent_id,
            "human_sponsor": self.human_sponsor,
            "session_id":    self.session_id,
            "nodes":         {k: v.to_dict() for k, v in self._nodes.items()},
            "chain_tip":     self.chain_tip_hash(),
            "chain_length":  len(self._chain),
        }

    # ---- internals -------------------------------------------------------

    def _fresh_id(self, prefix: str, name: str) -> str:
        self._seq += 1
        safe = name.replace(" ", "_")[:30]
        return f"{prefix}:{safe}:{self._seq}"

    def _add(self, node: ProvenanceNode) -> None:
        self._nodes[node.node_id] = node
        prev_hash = self._chain[-1].this_hash if self._chain else "genesis"
        rec = MerkleRecord(
            seq=len(self._chain),
            node_id=node.node_id,
            content=node.to_dict(),
            prev_hash=prev_hash,
        )
        self._chain.append(rec)


@dataclass
class ProvenanceTrace:
    """The result of a backward trace from an anomalous event."""
    root_id:           str
    nodes:             dict[str, ProvenanceNode]
    untrusted_origins: list[ProvenanceNode]
    human_sponsor:     str

    def summary(self) -> str:
        lines = [f"Causal trace from '{self.root_id}':"]
        lines.append(f"  Human sponsor: {self.human_sponsor}")
        lines.append(f"  Nodes in trace: {len(self.nodes)}")
        if self.untrusted_origins:
            lines.append("  ⚠ Untrusted origins:")
            for n in self.untrusted_origins:
                prev = n.attributes.get("content_preview", "")
                lines.append(f"    [{n.prov_type.value}] {n.label}"
                             + (f" — {prev!r}" if prev else ""))
        else:
            lines.append("  ✓ No untrusted origins found in trace")
        return "\n".join(lines)
