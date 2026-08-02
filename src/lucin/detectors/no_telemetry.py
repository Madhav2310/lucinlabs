"""AG-028: Execution Without Telemetry/Monitoring.

Detects agent configurations that have code execution or tool calling capability
but no logging, telemetry, or monitoring configured.

This is the EXACT failure that enabled the Hugging Face breach (July 2026):
- An evaluation environment (ExploitGym) ran a cyber-capable OpenAI model without
  default monitoring
- The model operated for roughly two and a half days before discovery
- ~17,600 actions executed without any logging

Real-world basis:
- Hugging Face breach (July 2026): an OpenAI model escaped its ExploitGym
  evaluation sandbox and reached Hugging Face's infrastructure
- Key failure: evaluation systems not monitored by default
- If monitoring had been on, the escape would have been detected far sooner

Detection logic:
- Agent has EXECUTE_CODE or HIGH-RISK tools (3+ tools with capabilities)
- Source code/config does NOT contain monitoring indicators
- Monitoring indicators: logging, telemetry, otel, callbacks, tracing, audit
"""

from pathlib import Path

from lucin.models import Agent, Finding, Severity, ToolCapability
from lucin.owasp import owasp_ref

# Indicators that monitoring/telemetry IS configured.
# Corpus lesson: agentops is the most common telemetry framework (244 imports
# in the agentops repo alone). These SDK-level telemetry tools wrap the entire
# agent session — they satisfy the monitoring requirement even though they don't
# appear as per-tool logging calls.
MONITORING_INDICATORS = [
    # Standard Python logging
    "logging", "logger", "log.", "log(",
    # OpenTelemetry (industry standard, used by AutoGen, many others)
    "telemetry", "otel", "opentelemetry", "tracing", "trace(", "tracer",
    # LLM-specific observability platforms
    "langfuse", "langsmith", "phoenix", "arize",
    "wandb", "mlflow", "logfire",
    # Agent-specific monitoring (corpus-derived: most common pattern)
    "agentops", "agentops.init", "agentops.start_trace",
    "weave", "traceloop",
    # Callbacks (LangChain pattern for session-level monitoring)
    "callback", "callbacks",
    # Generic audit
    "audit", "audit_log", "monitor", "monitoring", "observe", "observability",
    # APM tools
    "sentry", "datadog", "newrelic",
]


def detect_no_telemetry(agent: Agent) -> list[Finding]:
    """Detect agents with execution capability but no monitoring."""
    findings = []

    # Only flag agents with high-risk capabilities
    has_exec = any(ToolCapability.EXECUTE_CODE in t.capabilities for t in agent.tools)
    has_many_tools = len(agent.tools) >= 3
    has_network = any(ToolCapability.NETWORK_ACCESS in t.capabilities for t in agent.tools)
    has_write = any(ToolCapability.WRITE_DATA in t.capabilities for t in agent.tools)

    # Only flag when there is genuine execution/mutation risk.
    # A CrewAI crew of web-search + scrape tools (network-only, no exec/write)
    # is a FP: it has many network tools but cannot execute or mutate state.
    # Galaxy-style risk requires exec OR (network egress AND write/mutation).
    risky = has_exec or (has_many_tools and has_network and (has_write or has_exec))
    if not risky:
        return findings  # Low-risk agent — monitoring less critical

    # Check if source code mentions any monitoring
    if not agent.source_file:
        return findings

    try:
        content = Path(agent.source_file).read_text(encoding="utf-8")
    except (FileNotFoundError, PermissionError):
        return findings

    content_lower = content.lower()

    # Check for monitoring indicators
    has_monitoring = any(ind in content_lower for ind in MONITORING_INDICATORS)

    if not has_monitoring:
        tool_names = ", ".join(t.name for t in agent.tools[:5])
        findings.append(Finding(
            id="AG-028",
            title="Execution Without Telemetry/Monitoring",
            severity=Severity.HIGH,
            description=(
                f"Agent '{agent.name}' has high-risk capabilities ({tool_names}) "
                f"but no logging, telemetry, or monitoring is configured.\n\n"
                f"Without monitoring, malicious or anomalous agent behavior can continue "
                f"undetected for extended periods. In the Hugging Face breach (July 2026), "
                f"an OpenAI model operated unmonitored for roughly two and a half days, "
                f"taking an estimated 17,600 actions before detection."
            ),
            agent_name=agent.name,
            attack_scenario=(
                "1. Agent is deployed with execution capabilities but no logging\n"
                "2. Agent is compromised (via prompt injection) or behaves anomalously\n"
                "3. Malicious actions (data exfil, lateral movement, persistence) occur\n"
                "4. No alerts fire — team discovers breach days or weeks later\n"
                "5. Forensic analysis is impossible without logs"
            ),
            blast_radius=(
                "Unknown — without monitoring, the full scope of compromise cannot be determined. "
                "The Hugging Face breach involved an estimated 17,600 actions across four services."
            ),
            owasp_ref=owasp_ref("AG-028"),
            fix_suggestion=(
                "Add observability to your agent:\n"
                "  → LangChain: Add LangSmith or Langfuse callbacks\n"
                "  → LangGraph: Enable tracing with langsmith_api_key\n"
                "  → Any framework: Add OpenTelemetry GenAI semantic conventions\n"
                "  → Minimum: import logging; logger = logging.getLogger(__name__)\n"
                "  → Best: Full OTel tracing with span-per-tool-call"
            ),
            source_file=agent.source_file,
        ))

    return findings
