"""AG-005: Detect dangerous tool combinations."""

from lucin.models import Agent, Finding, Severity, ToolCapability
from lucin.owasp import owasp_ref


DANGEROUS_COMBOS = [
    {
        "requires": [ToolCapability.READ_DATA, ToolCapability.EXECUTE_CODE],
        "id": "AG-005a",
        "title": "Database Access + Code Execution",
        "severity": Severity.HIGH,
        "description": "Agent can read data AND execute code — enables data theft via code execution.",
        "owasp": owasp_ref("AG-005a"),
    },
    {
        "requires": [ToolCapability.EXECUTE_CODE, ToolCapability.NETWORK_ACCESS],
        "id": "AG-005b",
        "title": "Code Execution + Network Access",
        "severity": Severity.HIGH,
        "description": "Agent can execute code AND access network — enables reverse shell or C2.",
        "owasp": owasp_ref("AG-005b"),
    },
    # NOTE (H4): the former AG-005c (WRITE_DATA + MODIFY_AGENT) was removed as a
    # proven no-op — no capability classifier ever emits ToolCapability.MODIFY_AGENT,
    # so the combo could never be satisfied and the rule never fired. Genuine
    # self-modification risk is covered by the AG-023 detector (self_modification.py),
    # which inspects code/tool patterns rather than a capability that is never set.
]


def detect_dangerous_combinations(agent: Agent) -> list[Finding]:
    """Detect dangerous tool capability combinations."""
    findings = []

    # Collect all capabilities across all tools
    all_capabilities = set()
    for tool in agent.tools:
        all_capabilities.update(tool.capabilities)

    for combo in DANGEROUS_COMBOS:
        required = set(combo["requires"])
        if required.issubset(all_capabilities):
            # Find the specific tools involved
            involved_tools = []
            for cap in required:
                for tool in agent.tools:
                    if cap in tool.capabilities and tool.name not in involved_tools:
                        involved_tools.append(tool.name)
                        break

            findings.append(Finding(
                id=combo["id"],
                title=combo["title"],
                severity=combo["severity"],
                description=(
                    f"{combo['description']}\n"
                    f"Tools involved: {', '.join(involved_tools)}"
                ),
                agent_name=agent.name,
                attack_scenario=(
                    f"Combined capabilities [{' + '.join(c.value for c in required)}] "
                    f"enable attack chains that individual tools cannot perform alone."
                ),
                blast_radius="Depends on scope of individual tool permissions.",
                owasp_ref=combo["owasp"],
                fix_suggestion=(
                    "Separate these capabilities into different agents with distinct permission scopes, "
                    "or add explicit approval gates between operations that combine these capabilities."
                ),
                source_file=agent.source_file,
            ))

    return findings
