"""AG-024: Cross-Origin MCP Escalation.

Detects when the combination of multiple MCP servers creates unintended
access paths — where one server's tools can be used to access resources
that belong to a different server's domain.

The fundamental issue: MCP servers are designed independently. Server A
manages database access. Server B manages the filesystem. When an agent
connects to BOTH, it can potentially:
- Read DB credentials via Server A → use them to access the DB directly via Server B
- Read files via Server B → find API keys → use Server A's HTTP tool to exfiltrate
- Combine Server A's read capability with Server B's write capability

This is the "confused deputy" problem applied to MCP architecture:
the agent acts as a deputy for BOTH servers, and can violate the
trust boundaries between them.

Real-world basis:
- OWASP MCP Top 10: Cross-origin escalation is explicitly called out
- Palo Alto Unit 42: 78.3% attack success with 5 connected MCP servers
- NSA MCP guidance: warns about trust boundary violations between servers
- The more servers connected, the exponentially more cross-origin paths exist
"""

import re
from itertools import combinations

from lucin.models import Agent, Finding, MCPServer, Severity, ToolCapability
from lucin.owasp import owasp_ref


def _name_signals(name_lower: str, keywords: list[str]) -> bool:
    """Token-boundary keyword match on a server NAME (E3).

    The old check was a raw `kw in name_lower` substring test, so a 2–3 char
    keyword mis-inferred capabilities from unrelated names: `"db"` matched
    `sandbox`/`feedback`, `"fs"` matched `offset`, `"git"` matched `legitimate`,
    `"api"` matched `rapid`, `"web"` matched `cobweb`. We match short keywords
    only as WHOLE tokens (split on non-alphanumerics); distinctive long keywords
    (>=6 chars, e.g. `postgres`, `database`, `filesystem`) may still match as a
    substring to catch morphological variants (`postgresql`).
    """
    tokens = set(re.split(r"[^a-z0-9]+", name_lower))
    for kw in keywords:
        if kw in tokens:
            return True
        if len(kw) >= 6 and kw in name_lower:
            return True
    return False


# Dangerous cross-origin combinations
DANGEROUS_CROSS_COMBOS = [
    {
        "server_a_capability": "read",  # Can read data
        "server_b_capability": "network",  # Can send externally
        "risk": "Data from Server A can be exfiltrated via Server B's network tool",
        "severity": Severity.HIGH,
    },
    {
        "server_a_capability": "read",  # Can read files/data
        "server_b_capability": "exec",  # Can execute code
        "risk": "Credentials read from Server A can be used via Server B's code execution",
        "severity": Severity.HIGH,
    },
    {
        "server_a_capability": "network",  # Can fetch external data
        "server_b_capability": "write",  # Can write to filesystem/DB
        "risk": "Malicious content from external sources (Server A) can be written to internal systems (Server B)",
        "severity": Severity.HIGH,
    },
    {
        "server_a_capability": "exec",  # Can run code
        "server_b_capability": "network",  # Can send externally
        "risk": "Code execution results (including secrets in environment) can be sent externally",
        "severity": Severity.CRITICAL,
    },
]


def detect_cross_origin(agent: Agent) -> list[Finding]:
    """Detect cross-origin escalation risks between MCP servers."""
    findings = []

    # Only relevant if agent has 2+ MCP servers
    if len(agent.mcp_servers) < 2:
        return findings

    # Analyze each pair of servers for cross-origin risks
    for server_a, server_b in combinations(agent.mcp_servers, 2):
        pair_findings = _analyze_server_pair(server_a, server_b, agent)
        findings.extend(pair_findings)

    # Overall risk assessment for high server count
    if len(agent.mcp_servers) >= 4:
        findings.append(Finding(
            id="AG-024",
            title="High Cross-Origin Risk: Many MCP Servers Connected",
            severity=Severity.MEDIUM,
            description=(
                f"Agent '{agent.name}' connects to {len(agent.mcp_servers)} MCP servers. "
                f"The number of potential cross-origin paths grows exponentially with "
                f"each additional server.\n\n"
                f"With {len(agent.mcp_servers)} servers, there are "
                f"{len(agent.mcp_servers) * (len(agent.mcp_servers) - 1) // 2} "
                f"unique server pairs — each a potential cross-origin escalation path.\n\n"
                f"Palo Alto Unit 42 found 78.3% attack success rate with 5 connected servers."
            ),
            agent_name=agent.name,
            attack_scenario=(
                "Each server pair creates a trust boundary crossing opportunity. "
                "An attacker only needs to exploit ONE server to pivot across all others "
                "via the agent acting as a confused deputy."
            ),
            blast_radius=f"All {len(agent.mcp_servers)} servers' resources are interconnected through the agent.",
            owasp_ref=owasp_ref("AG-024"),
            fix_suggestion=(
                "1. Minimize the number of MCP servers per agent (principle of least privilege)\n"
                "2. Use separate agents for separate concerns (don't connect filesystem + database + network to ONE agent)\n"
                "3. Implement cross-server access policies (Server A's data can't flow to Server B)\n"
                "4. Add data-flow boundaries between server contexts"
            ),
            source_file=agent.source_file,
        ))

    return findings


def _analyze_server_pair(server_a: MCPServer, server_b: MCPServer, agent: Agent) -> list[Finding]:
    """Analyze a pair of MCP servers for cross-origin risks."""
    findings = []

    # Determine capabilities of each server
    caps_a = _get_server_capabilities(server_a)
    caps_b = _get_server_capabilities(server_b)

    # Check against known dangerous combinations
    for combo in DANGEROUS_CROSS_COMBOS:
        a_has = combo["server_a_capability"] in caps_a
        b_has = combo["server_b_capability"] in caps_b

        # Check both directions
        if a_has and b_has:
            findings.append(Finding(
                id="AG-024",
                title=f"Cross-Origin Escalation: {server_a.name} × {server_b.name}",
                severity=combo["severity"],
                description=(
                    f"MCP servers '{server_a.name}' ({combo['server_a_capability']}) and "
                    f"'{server_b.name}' ({combo['server_b_capability']}) create a cross-origin "
                    f"escalation path:\n\n"
                    f"{combo['risk']}\n\n"
                    f"These servers were designed independently but the agent connects "
                    f"to both, creating an unintended bridge between their trust domains."
                ),
                agent_name=agent.name,
                attack_scenario=(
                    f"1. Attacker targets the agent with a prompt injection\n"
                    f"2. Agent uses '{server_a.name}' to {combo['server_a_capability']} data\n"
                    f"3. Agent passes that data to '{server_b.name}' for {combo['server_b_capability']}\n"
                    f"4. Cross-origin violation: data crosses trust boundary\n\n"
                    f"The agent acts as a 'confused deputy' — authorized to use both servers "
                    f"independently, but combining them violates intended isolation."
                ),
                blast_radius=(
                    f"Resources of both '{server_a.name}' and '{server_b.name}' "
                    f"become interconnected through the agent."
                ),
                owasp_ref=owasp_ref("AG-024"),
                fix_suggestion=(
                    f"1. Separate into different agents: one for '{server_a.name}', "
                    f"another for '{server_b.name}'\n"
                    f"2. Add cross-server data flow policy (prevent data from one server "
                    f"being passed to another)\n"
                    f"3. Use separate MCP sessions with different credential scopes"
                ),
                source_file=agent.source_file,
            ))

        # Also check reverse direction
        a_has_rev = combo["server_b_capability"] in caps_a
        b_has_rev = combo["server_a_capability"] in caps_b
        if a_has_rev and b_has_rev and not (a_has and b_has):
            # Same risk, reversed servers
            findings.append(Finding(
                id="AG-024",
                title=f"Cross-Origin Escalation: {server_b.name} × {server_a.name}",
                severity=combo["severity"],
                description=(
                    f"MCP servers '{server_b.name}' ({combo['server_a_capability']}) and "
                    f"'{server_a.name}' ({combo['server_b_capability']}) create a cross-origin "
                    f"escalation path:\n\n{combo['risk']}"
                ),
                agent_name=agent.name,
                attack_scenario="Cross-origin trust boundary violation via confused deputy pattern.",
                blast_radius="Resources of both servers exposed.",
                owasp_ref=owasp_ref("AG-024"),
                fix_suggestion="Separate these servers into different agents with distinct scopes.",
                source_file=agent.source_file,
            ))

    return findings


def _get_server_capabilities(server: MCPServer) -> set[str]:
    """Determine what capabilities an MCP server provides."""
    caps = set()

    for tool in server.tools:
        if ToolCapability.READ_DATA in tool.capabilities:
            caps.add("read")
        if ToolCapability.WRITE_DATA in tool.capabilities:
            caps.add("write")
        if ToolCapability.EXECUTE_CODE in tool.capabilities:
            caps.add("exec")
        if ToolCapability.NETWORK_ACCESS in tool.capabilities:
            caps.add("network")
        if ToolCapability.FILE_SYSTEM in tool.capabilities:
            caps.add("filesystem")

    # Infer from server name/type if tools don't have explicit capabilities.
    # Token-boundary matching (E3) — see _name_signals.
    name_lower = server.name.lower()
    if _name_signals(name_lower, ["postgres", "mysql", "database", "db", "sql"]):
        caps.add("read")
    if _name_signals(name_lower, ["filesystem", "file", "fs"]):
        caps.add("read")
        caps.add("write")
        caps.add("filesystem")
    if _name_signals(name_lower, ["fetch", "http", "web", "api"]):
        caps.add("network")
    if _name_signals(name_lower, ["shell", "exec", "code", "terminal"]):
        caps.add("exec")
    if _name_signals(name_lower, ["slack", "email", "notify", "send"]):
        caps.add("network")
    if _name_signals(name_lower, ["github", "git"]):
        caps.add("read")
        caps.add("network")

    return caps
