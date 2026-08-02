"""AG-003: Detect unauthenticated MCP servers and MCP auth misconfigurations."""

from lucin.models import Agent, Finding, Severity
from lucin.owasp import owasp_ref

# API provider tokens that should never be passed through to MCP servers.
# When these appear in an MCP server's env block, the MCP server can make
# API calls on the user's behalf — the token passthrough attack (RFC 8707).
_LLM_PROVIDER_TOKENS = {
    "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "OPENAI_API_BASE",
    "COHERE_API_KEY", "GOOGLE_API_KEY", "GROQ_API_KEY",
    "MISTRAL_API_KEY", "TOGETHER_API_KEY", "PERPLEXITY_API_KEY",
    "HUGGINGFACE_TOKEN", "HF_TOKEN", "REPLICATE_API_TOKEN",
}


def detect_unauthenticated_mcp(agent: Agent) -> list[Finding]:
    """Detect MCP servers with no authentication configured."""
    findings = []

    for server in agent.mcp_servers:
        if not server.has_authentication:
            tool_count = len(server.tools)
            findings.append(Finding(
                id="AG-003",
                title="Unauthenticated MCP Server",
                severity=Severity.HIGH,
                description=(
                    f"MCP server '{server.name}' ({server.transport} transport) "
                    f"has no authentication configured. "
                    f"Exposes {tool_count} tool(s) to any connecting client."
                ),
                agent_name=agent.name,
                attack_scenario=(
                    "Any process on the same machine (for stdio) or any network client "
                    "(for HTTP/SSE) can connect and invoke all exposed tools. "
                    "NSA guidance (May 2026) explicitly warns against this configuration."
                ),
                blast_radius=(
                    f"All {tool_count} tools on server '{server.name}' accessible without credentials."
                ),
                owasp_ref=owasp_ref("AG-003"),
                fix_suggestion=(
                    "Enable OAuth 2.1 authentication on this MCP server.\n"
                    "  See: https://modelcontextprotocol.io/specification/2025-11-25/basic/transports\n"
                    "  Minimum: Add client certificate validation or API key requirement."
                ),
                source_file=agent.source_file,
            ))

        # Also flag HTTP without TLS
        if server.transport in ("sse", "streamable_http") and not server.has_tls:
            findings.append(Finding(
                id="AG-012",
                title="Unencrypted MCP Transport",
                severity=Severity.MEDIUM,
                description=(
                    f"MCP server '{server.name}' uses {server.transport} transport "
                    f"without TLS encryption."
                ),
                agent_name=agent.name,
                attack_scenario=(
                    "Tool call parameters and responses transmitted in plaintext. "
                    "Network observers can intercept prompts, data, and credentials."
                ),
                blast_radius="All data flowing between agent and MCP server is visible to network observers.",
                owasp_ref=owasp_ref("AG-012"),
                fix_suggestion="Enable TLS. Use https:// URLs for MCP server connections.",
                source_file=agent.source_file,
            ))

    # Token passthrough detection (RFC 8707 audience binding violation):
    # An LLM provider API key in an MCP server's env block means the MCP server
    # can call the LLM API using the user's credentials — an attacker who
    # compromises the MCP server gains full API access.
    for server in agent.mcp_servers:
        passed_tokens = [
            k for k in server.env_vars
            if k.upper() in _LLM_PROVIDER_TOKENS
        ]
        if passed_tokens:
            findings.append(Finding(
                id="AG-MCP-TOKENLEAK",
                title=f"MCP Token Passthrough: LLM API Key in Server Env",
                severity=Severity.CRITICAL,
                description=(
                    f"MCP server '{server.name}' receives LLM provider API "
                    f"key(s) via env: {', '.join(passed_tokens)}.\n\n"
                    f"This is the token passthrough pattern warned against in "
                    f"RFC 8707 (OAuth 2.0 audience binding): the MCP server can "
                    f"make API calls with the user's LLM credentials and any "
                    f"attacker who compromises the MCP server inherits full API access."
                ),
                agent_name=agent.name,
                attack_scenario=(
                    "1. Attacker compromises or poisons the MCP server\n"
                    "2. MCP server uses the passed API key to make calls to the LLM API\n"
                    "3. All billing, rate limits, and data exposure happen under user's account\n"
                    "4. No user consent or visibility — the agent continues to appear normal\n\n"
                    "Also: if the MCP config file is readable by other processes, "
                    "the key is exposed at rest."
                ),
                blast_radius=(
                    f"Full access to the {', '.join(passed_tokens)} account(s): "
                    f"unlimited API calls, model fine-tuning, data access."
                ),
                owasp_ref=owasp_ref("AG-MCP-TOKENLEAK"),
                fix_suggestion=(
                    "1. Remove the LLM API key from the MCP server env block.\n"
                    "2. The MCP server should use its own credentials for any LLM calls it "
                    "needs — not the user's key.\n"
                    "3. If the MCP server legitimately needs LLM access, issue it a "
                    "scoped, rate-limited key with audience binding (RFC 8707) to prevent "
                    "use outside the intended server context."
                ),
                source_file=agent.source_file,
            ))

    return findings
