"""OpenTelemetry Schema for Agent Security Telemetry.

Defines the span attributes and conventions for collecting agent
telemetry in OTel format. This is the contract between:
- Agent instrumentation (what gets emitted)
- Lucin collector (what we consume for scoring)

Based on OpenTelemetry GenAI Semantic Conventions (Development status, 2026):
- gen_ai.* attributes for LLM interactions
- mcp.* attributes for MCP tool calls
- lucin.* attributes for security-specific data

Reference: https://github.com/open-telemetry/semantic-conventions-genai

Integration points:
- OpenLLMetry (traceloop) emits these spans automatically
- Minibridge MCP proxy can emit these with OTel support
- Custom instrumentation can use this schema directly
"""

# === SPAN NAMES ===
# Following OTel GenAI convention: "{mcp.method.name} {target}"

SPAN_AGENT_ACTION = "lucin.action"
SPAN_TOOL_CALL = "mcp.tool_call"
SPAN_LLM_INFERENCE = "gen_ai.inference"
SPAN_AGENT_SESSION = "lucin.session"


# === REQUIRED ATTRIBUTES (must be present for scoring) ===

REQUIRED_ATTRIBUTES = {
    "agent.id": "Unique identifier for the agent instance",
    "agent.tool.name": "Name of the tool being called",
    "agent.action.timestamp": "ISO 8601 timestamp of the action",
}

# === RECOMMENDED ATTRIBUTES (improve scoring accuracy) ===

RECOMMENDED_ATTRIBUTES = {
    "agent.session.id": "Session identifier (groups related actions)",
    "agent.user.id": "Human user who initiated the session",
    "agent.tool.parameters": "JSON-encoded tool call parameters",
    "agent.tool.result.size_bytes": "Size of tool response in bytes",
    "agent.action.latency_ms": "Time taken for the action in milliseconds",
    "agent.action.type": "Type: tool_call | inference | data_access",
    "agent.task.context": "Description of what the agent is supposed to be doing",
    "agent.delegation.depth": "How many agents deep (0 = root agent)",
}

# === SECURITY-SPECIFIC ATTRIBUTES (Lucin extensions) ===

SECURITY_ATTRIBUTES = {
    "lucin.risk_score": "Anomaly score 0-99 (computed by scorer)",
    "lucin.action_taken": "allow | alert | escalate | block",
    "lucin.contributing_factors": "JSON array of scoring factors",
    "lucin.baseline_complete": "Whether agent has been baselined (bool)",
    "lucin.drift_detected": "Whether concept drift was detected (bool)",
    "lucin.fingerprint_match": "Similarity to known fingerprint (0.0-1.0)",
}

# === MCP-SPECIFIC ATTRIBUTES ===

MCP_ATTRIBUTES = {
    "mcp.method.name": "MCP method (tools/call, resources/read, etc.)",
    "mcp.session.id": "MCP session identifier",
    "mcp.server.name": "Name of the MCP server being called",
    "mcp.server.transport": "Transport type: stdio | sse | streamable_http",
    "mcp.tool.name": "Specific tool being invoked",
    "mcp.tool.parameters": "JSON parameters passed to the tool",
}


# === EXAMPLE SPAN (for documentation) ===

EXAMPLE_SPAN = {
    "name": "mcp.tool_call sql_query",
    "kind": "CLIENT",
    "start_time": "2026-07-27T10:30:00.000Z",
    "end_time": "2026-07-27T10:30:00.050Z",
    "attributes": {
        "agent.id": "support-agent-001",
        "agent.session.id": "session-abc123",
        "agent.user.id": "user-jane",
        "agent.tool.name": "sql_query",
        "agent.tool.parameters": '{"query": "SELECT * FROM customers WHERE id = 123"}',
        "agent.tool.result.size_bytes": 1024,
        "agent.action.latency_ms": 45,
        "agent.action.type": "tool_call",
        "mcp.server.name": "postgres",
        "mcp.session.id": "mcp-session-xyz",
        "lucin.risk_score": 12,
        "lucin.action_taken": "allow",
        "lucin.baseline_complete": True,
    },
    "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
    "span_id": "00f067aa0ba902b7",
}


def validate_span(attributes: dict) -> tuple[bool, list[str]]:
    """Validate that a span has the required attributes for scoring.

    Returns:
        (is_valid, list of missing required attributes)
    """
    missing = []
    for attr, desc in REQUIRED_ATTRIBUTES.items():
        if attr not in attributes:
            missing.append(f"{attr} ({desc})")

    return len(missing) == 0, missing


def span_to_action_dict(attributes: dict) -> dict:
    """Convert OTel span attributes to the JSONL format expected by lucin monitor.

    This bridges between OTel collection and our existing monitor pipeline.
    """
    return {
        "timestamp": attributes.get("agent.action.timestamp", ""),
        "agent_id": attributes.get("agent.id", "unknown"),
        "session_id": attributes.get("agent.session.id", "default"),
        "tool": attributes.get("agent.tool.name", ""),
        "params": _safe_json_parse(attributes.get("agent.tool.parameters", "{}")),
        "user_id": attributes.get("agent.user.id", ""),
        "result_size": attributes.get("agent.tool.result.size_bytes", 0),
        "latency_ms": attributes.get("agent.action.latency_ms", 0),
    }


def _safe_json_parse(text: str) -> dict:
    """Safely parse JSON, returning empty dict on failure."""
    import json
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return {}
