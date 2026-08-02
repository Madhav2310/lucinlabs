"""Attack Path Visualization — show the chain that led to exploitation.

When a red team attack succeeds, this module produces a clear,
text-based visualization of the attack path:

    [User Input] → [Agent Processes] → [Tool Call 1] → [Tool Call 2] → [EXPLOIT]

This makes it immediately clear HOW the agent was compromised,
not just THAT it was compromised. Essential for remediation.

Similar to Wiz's attack path graphs but for agent exploitation chains.
"""

from dataclasses import dataclass

from lucin.redteam.runner import AttackResult, TestResult


@dataclass
class AttackPathNode:
    """A single node in an attack path."""
    step: int
    action: str
    detail: str
    risk_level: str  # "normal" | "suspicious" | "exploit"


def generate_attack_path(result: AttackResult) -> str:
    """Generate a text-based attack path visualization from an attack result.

    Returns a formatted string showing the exploitation chain.
    """
    if result.result != TestResult.FAILED:
        return ""  # Only generate paths for successful attacks

    attack = result.attack
    nodes = _build_path_nodes(attack, result)

    # Build visualization
    lines = []
    lines.append(f"  ╔══ Attack Path: {attack.name} ══╗")
    lines.append(f"  ║")

    for i, node in enumerate(nodes):
        # Color coding via text markers
        if node.risk_level == "exploit":
            prefix = "  ║ 🔴"
        elif node.risk_level == "suspicious":
            prefix = "  ║ 🟡"
        else:
            prefix = "  ║ ⚪"

        lines.append(f"{prefix} Step {node.step}: {node.action}")
        lines.append(f"  ║      {node.detail}")

        if i < len(nodes) - 1:
            lines.append(f"  ║      │")
            lines.append(f"  ║      ▼")

    lines.append(f"  ║")
    lines.append(f"  ║ Result: EXPLOITED")
    lines.append(f"  ║ Evidence: {', '.join(result.matched_indicators[:3])}")
    lines.append(f"  ║ OWASP: {attack.owasp_ref}")
    if attack.mitre_atlas:
        lines.append(f"  ║ MITRE: {attack.mitre_atlas}")
    lines.append(f"  ╚{'═' * 50}╝")

    return "\n".join(lines)


def _build_path_nodes(attack, result: AttackResult) -> list[AttackPathNode]:
    """Build the logical path nodes from attack metadata."""
    nodes = []

    # Node 1: Initial vector (user input or tool output)
    if attack.category.value == "prompt_injection":
        nodes.append(AttackPathNode(
            step=1,
            action="Prompt Injection Delivered",
            detail=f"Payload sent via user message ({len(attack.payload)} chars)",
            risk_level="suspicious",
        ))
    elif attack.category.value == "data_exfiltration":
        nodes.append(AttackPathNode(
            step=1,
            action="Social Engineering / Pretext",
            detail="Legitimate-sounding request that triggers data access",
            risk_level="normal",
        ))
    else:
        nodes.append(AttackPathNode(
            step=1,
            action="Attack Initiated",
            detail=f"Category: {attack.category.value}",
            risk_level="suspicious",
        ))

    # Node 2: Agent processes input
    nodes.append(AttackPathNode(
        step=2,
        action="Agent Processes Input",
        detail="Guardrails failed to block — agent proceeds with request",
        risk_level="suspicious",
    ))

    # Node 3: Exploitation action
    if "send" in attack.payload.lower() or "http" in attack.payload.lower():
        nodes.append(AttackPathNode(
            step=3,
            action="Tool Invocation (Data Exfiltration)",
            detail="Agent uses network tool to send data externally",
            risk_level="exploit",
        ))
    elif "exec" in attack.payload.lower() or "shell" in attack.payload.lower():
        nodes.append(AttackPathNode(
            step=3,
            action="Tool Invocation (Code Execution)",
            detail="Agent executes system command",
            risk_level="exploit",
        ))
    elif "credential" in attack.payload.lower() or "password" in attack.payload.lower():
        nodes.append(AttackPathNode(
            step=3,
            action="Data Access (Credential Theft)",
            detail="Agent reads sensitive credential data",
            risk_level="exploit",
        ))
    else:
        nodes.append(AttackPathNode(
            step=3,
            action="Exploitation Action",
            detail="Agent performs unauthorized action",
            risk_level="exploit",
        ))

    # Node 4: Impact
    nodes.append(AttackPathNode(
        step=4,
        action="Impact Achieved",
        detail=f"Severity: {attack.severity_if_successful.upper()} | Blast radius: agent's full permissions",
        risk_level="exploit",
    ))

    return nodes


def generate_all_attack_paths(results: list[AttackResult]) -> str:
    """Generate attack paths for all successful attacks."""
    exploited = [r for r in results if r.result == TestResult.FAILED]
    if not exploited:
        return "  No successful attacks — all paths blocked."

    paths = []
    for result in exploited:
        path = generate_attack_path(result)
        if path:
            paths.append(path)

    return "\n\n".join(paths)
