"""AG-002: Detect data exfiltration paths (read + send without boundary).

Enhanced with body-inspection intelligence:
- If human approval is configured, downgrade to HIGH (not CRITICAL)
- If network tool has URL allowlist, downgrade to MEDIUM
- Name the specific read→send pairs for actionability
- Consider whether tools are sandboxed
"""

from lucin.models import Agent, Finding, Severity, ToolCapability


def detect_data_exfiltration(agent: Agent) -> list[Finding]:
    """Detect agents that can both read sensitive data AND send it externally."""
    findings = []

    # Find tools that can read data
    read_tools = [
        t for t in agent.tools
        if ToolCapability.READ_DATA in t.capabilities
        or ToolCapability.FILE_SYSTEM in t.capabilities
    ]

    # Find tools that can SEND data externally (not just fetch/search).
    # Web-search, scrape, and browse tools pull data IN — they are sources,
    # not exfiltration sinks. Only flag tools whose name/description suggests
    # outbound data transfer (email, post, webhook, notify, etc.).
    # Suppress pure-fetch tools (web search, scrape) that pull data IN —
    # they are sources not sinks. Use name-prefix matching only to avoid
    # over-suppressing (e.g. "browse" alone could be bidirectional).
    _FETCH_ONLY_KEYWORDS = (
        # Known search/retrieval service names
        "web_search", "web_search_tool", "serperdev", "tavily",
        "scrapewebsite", "websitesearch", "firecrawl",
        "bing_search", "google_search", "duckduckgo", "exa",
        # Semantic read-only patterns: any tool whose name contains these
        # is almost certainly returning data, not sending it out.
        "search", "retrieve", "lookup", "query_", "fetch_",
        "get_content", "get_result",
    )
    send_tools = [
        t for t in agent.tools
        if ToolCapability.NETWORK_ACCESS in t.capabilities
        and not getattr(t, "is_fetch_only", False)          # body-inspection derived
        and not any(kw in t.name.lower() for kw in _FETCH_ONLY_KEYWORDS)
    ]

    # If an agent has BOTH read and send capabilities with no boundary, flag it.
    # Severity is graduated: READ+NETWORK alone is common and often benign (a weather
    # bot reads local state AND calls an API). Escalate only when there is evidence
    # the READ tool accesses sensitive data (secrets, files, DBs) AND the NETWORK tool
    # is not constrained to an internal/allowlisted destination.
    if read_tools and send_tools:
        read_names = ", ".join(t.name for t in read_tools[:5]) or "(unnamed tools)"
        send_names = ", ".join(t.name for t in send_tools[:5]) or "(unnamed tools)"

        # Mitigating controls
        has_dlp = any(
            "dlp" in t.name.lower() or "filter" in t.name.lower() or "sanitize" in t.name.lower()
            for t in agent.tools
        )
        has_human_approval = agent.has_human_in_loop
        has_sandbox = any(t.has_sandbox for t in send_tools)
        has_url_allowlist = any(
            "allowlist" in t.description.lower() or "whitelist" in t.description.lower()
            for t in send_tools
        )

        if has_dlp:
            return findings  # DLP in place — don't flag

        # Aggravating factors: read tool accesses sensitive data sources
        sensitive_read_keywords = {
            "secret", "credential", "password", "token", "key", "database",
            "db", "sql", "env", "config", "private", "pii", "ssn", "auth",
        }
        has_sensitive_read = any(
            any(kw in t.name.lower() for kw in sensitive_read_keywords)
            or ToolCapability.FILE_SYSTEM in t.capabilities
            for t in read_tools
        )

        # Severity ladder (Phase 0 fix — was unconditionally CRITICAL):
        # CRITICAL: sensitive read + unconstrained external network
        # HIGH:     sensitive read with human-in-loop, OR no-sensitive-read with exec also present
        # MEDIUM:   plain READ+NETWORK, constrained network, or human approval
        has_exec = any(ToolCapability.EXECUTE_CODE in t.capabilities for t in agent.tools)

        if has_sandbox or has_url_allowlist:
            severity = Severity.MEDIUM
        elif has_human_approval:
            severity = Severity.HIGH
        elif has_sensitive_read:
            severity = Severity.CRITICAL if has_exec else Severity.HIGH
        else:
            # Plain READ+NETWORK with no exec and no sensitive-read signal — MEDIUM
            severity = Severity.MEDIUM

        # Build specific exfil paths for actionability
        paths = []
        for r in read_tools[:3]:
            for s in send_tools[:3]:
                paths.append(f"{r.name} → {s.name}")
        path_desc = "; ".join(paths)

        findings.append(Finding(
            id="AG-002",
            title="Data Exfiltration Path",
            severity=severity,
            description=(
                f"Agent '{agent.name}' can read data (via: {read_names}) "
                f"and send externally (via: {send_names}) with no data-flow boundary.\n\n"
                f"Exfiltration paths: {path_desc}\n\n"
                f"This creates a direct path from sensitive data sources to external networks."
            ),
            agent_name=agent.name,
            attack_scenario=(
                "A prompt injection could instruct the agent to: "
                "1) Query sensitive data using read tools, "
                "2) Send that data to an attacker-controlled endpoint using network tools. "
                "No guardrail prevents this data flow."
            ),
            blast_radius=(
                f"All data accessible via: {read_names}. "
                f"Could include PII, credentials, financial data, or proprietary information."
            ),
            owasp_ref="A06 - Cascading Hallucination Failures",
            fix_suggestion=(
                "Options:\n"
                "  1. Remove network access tool from this agent (separation of concerns)\n"
                "  2. Add a DLP/sanitization layer between read and send operations\n"
                "  3. Restrict network tool to allowlisted URLs only\n"
                "  4. Add human approval for any operation combining data read + external send"
            ),
            source_file=agent.source_file,
        ))

    return findings
