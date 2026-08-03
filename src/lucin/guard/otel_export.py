"""MATURITY: L2 (scaffolded + unit-tested on author input; NOT validated against a real framework/store).

OpenTelemetry export for the runtime provenance graph.

Converts a :class:`~lucin.guard.provenance.ProvenanceGraph` into
OpenTelemetry GenAI semantic-convention spans, and produces a human-readable
"why did this happen?" backward-trace report.

opentelemetry is NOT a dependency. :func:`to_otel_spans` emits plain ``dict``
objects shaped like OTel spans (``gen_ai.*`` attributes per the GenAI semantic
conventions), so this module imports cleanly with no OTel installed. If the
opentelemetry SDK *is* importable, :func:`export_via_otel` will emit real spans
through a provided tracer (lazy import — only touched when called).

GenAI semantic conventions reference:
  https://opentelemetry.io/docs/specs/semconv/gen-ai/
"""

from __future__ import annotations

from typing import Any

from lucin.guard.provenance import ProvenanceGraph, ProvenanceNode, ProvType

# GenAI convention span kinds we map onto. ACTIVITY nodes are the "operations";
# ENTITY/AGENT nodes are represented as spans too so the full lineage is visible.
_OTEL_KIND = {
    ProvType.ACTIVITY: "gen_ai.execute_tool",
    ProvType.ENTITY: "gen_ai.entity",
    ProvType.AGENT: "gen_ai.agent",
}


def to_otel_spans(prov: ProvenanceGraph) -> list[dict]:
    """Convert provenance nodes/activities to OpenTelemetry GenAI span dicts.

    Each returned dict has the shape::

        {
            "name":       "gen_ai.execute_tool fetch_email",
            "span_id":    "a:fetch_email:3",
            "trace_id":   "<session_id>",
            "kind":       "SPAN_KIND_INTERNAL",
            "start_time": <unix float>,
            "attributes": {
                "gen_ai.operation.name": "execute_tool",
                "gen_ai.tool.name":      "fetch_email",
                "gen_ai.agent.id":       "support-agent-42",
                "lucin.prov.type":  "activity",
                "lucin.prov.used":  ["e:..."],
                ...
            },
            "links": [ {"span_id": "<parent>", "type": "was_generated_by"}, ... ],
        }

    Non-standard, Lucin-specific fields are namespaced under
    ``lucin.*`` so they don't collide with GenAI reserved keys. PROV edges
    become span links.
    """
    spans: list[dict] = []
    for node in prov.to_dict()["nodes"].values():
        spans.append(_node_to_span(node, prov))
    return spans


def _node_to_span(node: dict, prov: ProvenanceGraph) -> dict:
    prov_type = node["type"]
    label = node["label"]
    attrs: dict[str, Any] = {
        "gen_ai.agent.id": prov.agent_id,
        "gen_ai.conversation.id": prov.session_id,
        "lucin.prov.type": prov_type,
        "lucin.prov.node_id": node["id"],
        "lucin.human_sponsor": prov.human_sponsor,
    }

    if prov_type == ProvType.ACTIVITY.value:
        attrs["gen_ai.operation.name"] = "execute_tool"
        attrs["gen_ai.tool.name"] = label
        node_attrs = node.get("attributes", {})
        if node_attrs.get("inputs"):
            attrs["gen_ai.tool.inputs"] = _stringify(node_attrs["inputs"])
        if node_attrs.get("triggered_by"):
            attrs["lucin.triggered_by"] = node_attrs["triggered_by"]
    elif prov_type == ProvType.ENTITY.value:
        attrs["gen_ai.operation.name"] = "entity"
        node_attrs = node.get("attributes", {})
        for k in ("integrity", "confidentiality", "content_preview"):
            if k in node_attrs:
                attrs[f"lucin.{k}"] = node_attrs[k]
    else:  # agent
        attrs["gen_ai.operation.name"] = "agent"

    links: list[dict] = []
    for edge_kind in ("was_generated_by", "was_derived_from",
                      "was_attributed_to", "used"):
        for target in node.get(edge_kind, []):
            links.append({"span_id": target, "type": edge_kind})

    return {
        "name": f"{_OTEL_KIND.get(ProvType(prov_type), 'gen_ai')} {label}",
        "span_id": node["id"],
        "trace_id": prov.session_id,
        "kind": "SPAN_KIND_INTERNAL",
        "start_time": node["timestamp"],
        "attributes": attrs,
        "links": links,
    }


def _stringify(value: Any) -> str:
    import json

    try:
        return json.dumps(value, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return str(value)


def export_via_otel(prov: ProvenanceGraph, tracer: Any) -> int:
    """Emit real OpenTelemetry spans for `prov` through `tracer`.

    Lazy import: opentelemetry is only touched here. Raises ImportError if the
    SDK is unavailable. `tracer` is an opentelemetry ``Tracer``. Returns the
    number of spans emitted.

    NOTE: this path is scaffolded and has NOT been exercised against a real
    OpenTelemetry SDK in this repo (no OTel installed).
    """
    try:
        from opentelemetry.trace import SpanKind  # noqa: F401
    except ImportError as exc:  # pragma: no cover - depends on optional dep
        raise ImportError(
            "opentelemetry is not installed; use to_otel_spans() for dict output"
        ) from exc

    count = 0
    for span_dict in to_otel_spans(prov):
        with tracer.start_as_current_span(span_dict["name"]) as span:
            for key, val in span_dict["attributes"].items():
                span.set_attribute(key, val)
        count += 1
    return count


def backward_trace_report(prov: ProvenanceGraph, node_id: str) -> dict:
    """Produce a human-readable "why did this happen?" chain for `node_id`.

    Uses :meth:`ProvenanceGraph.backward_trace` to walk from `node_id` back to
    its causal origins, then summarizes the chain to the root untrusted
    source(s) and the human sponsor.

    Returns a dict::

        {
            "root_id":            "e:email_body:2",
            "human_sponsor":      "user:alice",
            "session_id":         "...",
            "agent_id":           "...",
            "nodes_in_trace":     4,
            "chain":              [ {node summaries, root-most first}, ... ],
            "untrusted_origins":  [ {origin summaries}, ... ],
            "is_untrusted_origin": True,
            "explanation":        "<one-paragraph natural-language summary>",
        }
    """
    trace = prov.backward_trace(node_id)

    # Order chain by timestamp (root cause first -> effect last) for readability.
    ordered = sorted(trace.nodes.values(), key=lambda n: n.timestamp)
    chain = [_node_summary(n) for n in ordered]

    # `trace.untrusted_origins` only lists TOPOLOGICAL roots that are untrusted.
    # For "why did this happen?" we also want any untrusted node ANYWHERE in the
    # causal chain (e.g. a poisoned memory entity produced by a fetch activity is
    # not a topological root but IS the untrusted source we care about).
    untrusted_any = [
        n for n in ordered if n.attributes.get("integrity") == "untrusted"
    ]
    origins = [_node_summary(n) for n in untrusted_any]

    explanation = _build_explanation(node_id, trace.nodes.get(node_id),
                                     untrusted_any, trace.human_sponsor)

    return {
        "root_id": node_id,
        "human_sponsor": trace.human_sponsor,
        "session_id": prov.session_id,
        "agent_id": prov.agent_id,
        "nodes_in_trace": len(trace.nodes),
        "chain": chain,
        "untrusted_origins": origins,
        "topological_untrusted_origins": [
            _node_summary(n) for n in trace.untrusted_origins
        ],
        "is_untrusted_origin": bool(untrusted_any),
        "explanation": explanation,
    }


def _node_summary(node: ProvenanceNode) -> dict:
    return {
        "id": node.node_id,
        "type": node.prov_type.value,
        "label": node.label,
        "timestamp": node.timestamp,
        "integrity": node.attributes.get("integrity"),
        "content_preview": node.attributes.get("content_preview", ""),
    }


def _build_explanation(node_id: str, target: ProvenanceNode | None,
                       untrusted_origins: list[ProvenanceNode],
                       human_sponsor: str) -> str:
    target_label = target.label if target is not None else node_id
    if untrusted_origins:
        origin_desc = "; ".join(
            f"{o.label!r}"
            + (f" ({o.attributes['content_preview']!r})"
               if o.attributes.get("content_preview") else "")
            for o in untrusted_origins
        )
        return (
            f"Event '{target_label}' traces back to {len(untrusted_origins)} "
            f"UNTRUSTED origin(s): {origin_desc}. The session was sponsored by "
            f"human '{human_sponsor}'. Treat downstream actions as potentially "
            f"attacker-influenced."
        )
    return (
        f"Event '{target_label}' traces back only to trusted origins under "
        f"human sponsor '{human_sponsor}'. No untrusted source found in the "
        f"causal chain."
    )
