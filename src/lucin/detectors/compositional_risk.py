"""Compositional Risk Analysis — individually safe, dangerous together.

Per research paper "Benign in Isolation, Harmful in Composition" (arXiv:2606.15242):
Skills/tools that are individually safe can become dangerous when combined
in ways the original designers didn't anticipate.

Example:
- Tool A: "read_clipboard" (safe — just reads what user copied)
- Tool B: "send_message" (safe — just sends messages to contacts)
- Together: read_clipboard + send_message = automatic data exfiltration
  of anything the user copies (passwords from password manager, etc.)

This detector goes BEYOND simple pairwise capability analysis (AG-005).
It identifies N-way combinations that create emergent attack surfaces
not present in any individual tool.

The key insight: the WHOLE is more dangerous than the sum of its parts.
"""


from lucin.models import Agent, Finding, Severity, ToolCapability
from lucin.owasp import owasp_ref

# Dangerous N-way compositions — genuinely novel combinations not covered by AG-002/AG-005.
#
# NOTE (Phase 0): the original "Full Kill Chain: READ+EXEC+NETWORK" composition was
# removed because it directly double-counted AG-002 (DATA+NETWORK → CRITICAL) and
# AG-005b (EXEC+NETWORK → HIGH). Verified empirically: a 3-tool agent fires all three
# on the same fact. Double-counting inflates severity without adding signal.
# Kept: Persistence (WRITE+FS+memory — not covered by AG-002/AG-005) and
# Lateral Movement with ≥3 read sources (quantitative threshold no other detector
# checks). Add compositions here only when they flag something the others miss.
DANGEROUS_COMPOSITIONS = [
    {
        "name": "Persistence: Write + Memory + Self-Modify",
        "requires": [
            ToolCapability.WRITE_DATA,      # Can modify files
            ToolCapability.FILE_SYSTEM,      # Has filesystem access
        ],
        "extra_condition": lambda agent: agent.has_memory,  # Also has persistent memory
        "severity": Severity.HIGH,
        "description": (
            "Agent can write to filesystem AND has persistent memory. "
            "A compromised agent can persist its modifications across restarts "
            "by writing to config files or poisoning its own memory store."
        ),
        "attack_scenario": (
            "1. Agent is compromised via prompt injection\n"
            "2. Writes malicious instructions to its own config file\n"
            "3. On next restart, loads the poisoned config\n"
            "4. Compromise persists indefinitely without detection"
        ),
    },
    {
        "name": "Lateral Movement: Network + Multiple Data Sources",
        "requires": [
            ToolCapability.NETWORK_ACCESS,
            ToolCapability.READ_DATA,
        ],
        "min_read_tools": 3,  # Must have 3+ different read sources
        "severity": Severity.HIGH,
        "description": (
            "Agent has access to 3+ data sources AND network connectivity. "
            "Can aggregate data from multiple internal sources and exfiltrate "
            "a comprehensive dataset — more damaging than single-source access."
        ),
        "attack_scenario": (
            "1. Read from source A (customer DB)\n"
            "2. Read from source B (internal docs)\n"
            "3. Read from source C (credentials store)\n"
            "4. Aggregate and send ALL data via single network call\n"
            "Impact is multiplicative — not just one data source compromised."
        ),
    },
]


def detect_compositional_risk(agent: Agent) -> list[Finding]:
    """Detect emergent risks from tool compositions.

    Goes beyond pairwise analysis to find N-way combinations
    that create attack surfaces not present in individual tools.
    """
    findings = []

    # Collect all capabilities
    all_caps = set()
    for tool in agent.tools:
        all_caps.update(tool.capabilities)

    # Count tools per capability
    read_tools = [t for t in agent.tools if ToolCapability.READ_DATA in t.capabilities]
    [t for t in agent.tools if ToolCapability.WRITE_DATA in t.capabilities]
    [t for t in agent.tools if ToolCapability.EXECUTE_CODE in t.capabilities]
    [t for t in agent.tools if ToolCapability.NETWORK_ACCESS in t.capabilities]

    for composition in DANGEROUS_COMPOSITIONS:
        required = set(composition["requires"])

        if not required.issubset(all_caps):
            continue

        # Check extra conditions
        extra = composition.get("extra_condition")
        if extra and not extra(agent):
            continue

        min_read = composition.get("min_read_tools", 0)
        if min_read and len(read_tools) < min_read:
            continue

        # This composition is present
        involved_tools = []
        for cap in required:
            for tool in agent.tools:
                if cap in tool.capabilities and tool.name not in involved_tools:
                    involved_tools.append(tool.name)
                    break

        findings.append(Finding(
            id="AG-COMP",
            title=f"Compositional Risk: {composition['name']}",
            severity=composition["severity"],
            description=(
                f"{composition['description']}\n\n"
                f"Tools involved: {', '.join(involved_tools)}"
            ),
            agent_name=agent.name,
            attack_scenario=composition["attack_scenario"],
            blast_radius=(
                "Emergent attack surface from tool composition. "
                "Individual tools may pass review; the COMBINATION creates the vulnerability."
            ),
            owasp_ref=owasp_ref("AG-COMP"),
            fix_suggestion=(
                "1. Apply principle of least privilege: does this agent NEED all these capabilities?\n"
                "2. Separate into multiple agents with narrower scopes\n"
                "3. Add data-flow boundaries between capability groups\n"
                "4. Require human approval when combining capabilities across security domains"
            ),
            source_file=agent.source_file,
        ))

    return findings
