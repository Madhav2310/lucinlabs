"""Server-side runtime-AIFG reconstruction from telemetry (50_ §3.3, §5).

THIS IS THE "ONE COHERENT MODEL" STITCH IN CODE. The ingestion worker rebuilds a
runtime AIFG from a session's redacted event stream using the *same*
`lucin.aifg.AIFG` dataclass the static scanner uses — so `query_trifecta`
and `min_tool_cut` run UNCHANGED on the reconstructed graph (50_ §3.3). A finding
from SCAN and an enforcement from GUARD are the same object type: a labeled path
in the same IFC lattice (50_ §5).

We import the engine — we NEVER redefine AIFG/IFCLabel here (that would re-open
the exact "two models drift apart" risk 50_ §5/§6 exists to kill).

SCAFFOLD STATUS: node/label/edge construction below is real and runs today (it
imports the live engine). What is stubbed: (a) full provenance-lineage
reconstruction — 50_ §3.3 says the real worker reuses
`ProvenanceGraph.to_aifg()` for observed 1:1 lineage; here we approximate edges
from the witness paths carried in each event. (b) persistence of the resulting
`AIFG.to_dict()` to the object store (`aifg_object_key`). Both are marked TODO.
"""

from __future__ import annotations

from typing import Iterable

# Import the ONE shared engine — do not redefine these types here.
from lucin.aifg import (
    AIFG,
    AIFGEdge,
    AIFGNode,
    Confidentiality,
    EdgeKind,
    IFCLabel,
    Integrity,
    ifc_label_from_strings,
    query_trifecta,
)

# The LLM mediator node id (aifg.build_aifg). It is NEVER the untrusted-control
# ORIGIN (the C2 engine fix) — a witness-only LLM node must not be named as the
# attacker-influenceable source, only pass untrusted-ness through.
_LLM_NODE_ID = "__llm__"

from control_plane.api.schemas import TelemetryEventIn


def reconstruct_session_aifg(
    agent_id: str, events: Iterable[TelemetryEventIn]
) -> AIFG:
    """Rebuild a runtime AIFG for one agent/session from redacted telemetry.

    - each distinct `tool_name` -> an AIFGNode, label = the observed IFC label
      (decoded via the engine's canonical `ifc_label_from_strings`);
    - each witness edge "src -> dst" (tool names only) -> an AIFGEdge.

    The resulting graph is queryable by the identical algorithms as the static
    one (`query_trifecta`, `min_tool_cut`).
    """
    g = AIFG(agent_name=agent_id)
    events = list(events)

    # Pass 1: create/upsert nodes from events. Event data is AUTHORITATIVE (it
    # carries the observed IFC label + egress), so it must win over the
    # placeholder nodes a witness string may create in pass 2.
    for ev in events:
        if not ev.tool_name:
            continue
        # Decode the observed label using the SAME string->enum mapping the
        # static builder uses (single canonical vocabulary — aifg.py).
        result_label = ifc_label_from_strings(
            ev.ifc_result.integrity, ev.ifc_result.confidentiality
        )
        # Egress classification. TODO(stage-3): call
        # lucin.aifg.is_egress_by_name(tool_name, ...) with observed caps to
        # match the static classifier exactly rather than trusting `destination`.
        is_egress = ev.destination == "external"
        g.nodes[ev.tool_name] = AIFGNode(
            node_id=ev.tool_name,
            label=result_label,
            is_egress=is_egress,
            is_sink=is_egress,
        )

    # Pass 2: witness entries are structural tool-name paths
    # ("read_db →_data send_email") — parse them into edges over the same node
    # vocabulary. Any endpoint not seen as an event node is added as a
    # conservative placeholder (does not overwrite an authoritative event node).
    for ev in events:
        for hop in ev.witness:
            _add_witness_edges(g, hop)

    return g


def _witness_only_source_node(node_id: str, kind: str) -> AIFGNode:
    """Label a placeholder created for a witness endpoint we saw NO event for.

    The witness's edge-kind IS the source's role in the trifecta the runtime
    observed (aifg.py: control_path = "attacker can steer", data_path = "secret
    reaches payload"), so a witness-only source is labeled to that role instead of
    the neutral TRUSTED_PUBLIC default. Without this, a source that appears only
    inside another tool's witness (e.g. `web_fetch` when only `send_email` emitted
    its own event) reconstructs as TRUSTED/PUBLIC and `query_trifecta` MISSES a
    trifecta the runtime plainly witnessed — the "witness-only-source miss".

    Conservative-but-faithful, matching the static builder's "unknown integrity →
    UNTRUSTED" convention (aifg._label_for_tool):
      * CONTROL-edge source → UNTRUSTED integrity (the untrusted-control origin);
        `is_untrusted_input` names the real origin, but NEVER for the LLM mediator
        (C2: the LLM is not the untrusted ORIGIN).
      * DATA-edge source → INTERNAL confidentiality (the secret data origin).
    An authoritative event node from pass 1 is never routed here (we only build
    this for endpoints missing from `g.nodes`), so observed labels always win.
    """
    if kind == EdgeKind.CONTROL:
        return AIFGNode(
            node_id=node_id,
            label=IFCLabel(Integrity.UNTRUSTED, Confidentiality.PUBLIC),
            is_untrusted_input=(node_id != _LLM_NODE_ID),
        )
    return AIFGNode(
        node_id=node_id,
        label=IFCLabel(Integrity.UNTRUSTED, Confidentiality.INTERNAL),
        is_source=True,
    )


def _add_witness_edges(g: AIFG, witness: str) -> None:
    """Parse a witness string into AIFGEdges (best-effort, additive).

    Witness formats seen in the engine (aifg.py TrifectaFinding, otel_export):
      "read_db →_data send_email"      (arrow with edge-kind hint)
      "web_fetch →_control send_email"
      "a -> b -> c"                    (plain chain)
    TODO(stage-3): replace this string parse with structured provenance
    (ProvenanceGraph.to_aifg) so edge kinds are authoritative, not inferred.
    """
    text = witness.replace("→", "->")
    kind = EdgeKind.CONTROL if "_control" in text else EdgeKind.DATA
    # normalize the "->_data" / "->_control" markers to a plain separator
    for marker in ("->_data", "->_control"):
        text = text.replace(marker, "->")
    parts = [p.strip() for p in text.split("->") if p.strip()]
    for src, dst in zip(parts, parts[1:]):
        # The destination is a downstream/mediator node — a neutral conservative
        # placeholder (its own egress/label come from its event in pass 1).
        if dst not in g.nodes:
            g.nodes[dst] = AIFGNode(node_id=dst)
        # The SOURCE carries the witness's declared role; if we never saw an event
        # for it, label it to that role so the trifecta is not silently missed.
        if src not in g.nodes:
            g.nodes[src] = _witness_only_source_node(src, kind)
        g.edges.append(AIFGEdge(src, dst, kind))


def query_runtime_trifecta(g: AIFG):
    """Run the UNCHANGED engine trifecta query on the reconstructed graph.

    Returns the same `TrifectaFinding` shape as the static path — this is the
    coherence guarantee (50_ §5, tests/test_aifg_coherence.py).
    """
    return query_trifecta(g)
