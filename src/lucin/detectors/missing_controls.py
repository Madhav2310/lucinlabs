"""AG-006, AG-009, AG-010: Missing security controls detection."""

import re
from pathlib import Path

from lucin.models import Agent, Finding, Severity, ToolCapability
from lucin.owasp import owasp_ref

# Framework-level HITL patterns recognized from the corpus.
# These exist at the orchestration layer (not per-tool), but they ARE genuine
# human-in-the-loop gates. Static analysis gives credit for them even though
# they don't appear as explicit tool-level callbacks.
_FRAMEWORK_HITL_PATTERNS = [
    # LangGraph: interrupt_before/interrupt_after on graph nodes
    r"interrupt_before",
    r"interrupt_after",
    # LangChain: human approval callback
    r"HumanApprovalCallbackHandler",
    # AutoGen: human_input_mode set to anything other than NEVER
    r'human_input_mode\s*=\s*["\'](?:ALWAYS|TERMINATE|AUTO)["\']',
    # CrewAI: human_input=True on a task
    r"human_input\s*=\s*True",
    # Agno: @tool(requires_confirmation=True) decorator (corpus: agno cookbook 2026-07-28)
    r"requires_confirmation\s*=\s*True",
    # General confirmation patterns
    r"require_confirmation",
    r"human_in_the_loop",
    r"approval_required",
]

# AutoGen's explicit HITL-bypass: human_input_mode='NEVER' with exec = AG-026,
# but we also use it here to ensure AG-006 still fires (belt-and-suspenders).
_HITL_DISABLED_PATTERN = re.compile(
    r'human_input_mode\s*=\s*["\']NEVER["\']'
)


def _has_framework_hitl(source_file: str) -> bool:
    """Check if the source file contains framework-level HITL patterns."""
    if not source_file:
        return False
    try:
        content = Path(source_file).read_text(encoding="utf-8")
    except Exception:
        return False
    return any(re.search(p, content) for p in _FRAMEWORK_HITL_PATTERNS)


def detect_missing_controls(agent: Agent) -> list[Finding]:
    """Detect missing security controls on agent configurations."""
    findings = []

    # AG-006: No human-in-the-loop for destructive actions.
    # Credit both the model flag AND framework-level HITL patterns from the corpus
    # (LangGraph interrupt_before, CrewAI human_input=True, AutoGen ALWAYS/TERMINATE).
    destructive_tools = [
        t for t in agent.tools
        if ToolCapability.EXECUTE_CODE in t.capabilities
        or ToolCapability.WRITE_DATA in t.capabilities
    ]

    has_hitl = agent.has_human_in_loop or _has_framework_hitl(agent.source_file)

    if destructive_tools and not has_hitl:
        tool_names = ", ".join(t.name for t in destructive_tools[:5])
        findings.append(Finding(
            id="AG-006",
            title="No Human Approval for Destructive Actions",
            severity=Severity.HIGH,
            description=(
                f"Agent '{agent.name}' has {len(destructive_tools)} tool(s) capable of "
                f"destructive actions ({tool_names}) but no human-in-the-loop approval configured.\n"
                f"The agent can autonomously execute, write, or delete without confirmation."
            ),
            agent_name=agent.name,
            attack_scenario=(
                "Without human approval gates, a prompt injection or hallucination can cause "
                "irreversible damage (data deletion, unauthorized writes, system modification) "
                "with no opportunity for a human to intervene."
            ),
            blast_radius=(
                f"All resources accessible to: {tool_names}. "
                f"Actions are irreversible once executed."
            ),
            owasp_ref=owasp_ref("AG-006"),
            fix_suggestion=(
                "Add human-in-the-loop for high-risk actions:\n"
                "  → LangGraph: use interrupt_before on destructive nodes\n"
                "  → LangChain: use HumanApprovalCallbackHandler\n"
                "  → General: require confirmation for write/delete/execute operations"
            ),
            source_file=agent.source_file,
        ))

    # AG-009: Can spawn sub-agents without limits
    if agent.can_spawn_subagents:
        findings.append(Finding(
            id="AG-009",
            title="Unlimited Sub-Agent Spawning",
            severity=Severity.MEDIUM,
            description=(
                f"Agent '{agent.name}' can create or delegate to sub-agents "
                f"with no apparent recursion limit or spawn control."
            ),
            agent_name=agent.name,
            attack_scenario=(
                "An attacker could trigger recursive agent spawning (fork bomb), "
                "causing resource exhaustion. Or a compromised sub-agent could spawn "
                "additional agents to amplify its access scope."
            ),
            blast_radius="Potential infinite resource consumption; cascading compromise across sub-agents.",
            owasp_ref=owasp_ref("AG-009"),
            fix_suggestion=(
                "Set explicit limits on:\n"
                "  → Maximum recursion depth for agent delegation\n"
                "  → Maximum number of concurrent sub-agents\n"
                "  → Total compute/token budget per agent session"
            ),
            source_file=agent.source_file,
        ))

    # AG-010: No rate limiting on tool calls
    has_rate_limit = any(t.has_rate_limit for t in agent.tools)
    if agent.tools and not has_rate_limit:
        exec_tools = [t for t in agent.tools if ToolCapability.EXECUTE_CODE in t.capabilities]
        network_tools = [t for t in agent.tools if ToolCapability.NETWORK_ACCESS in t.capabilities]
        high_risk_tools = exec_tools + network_tools

        if high_risk_tools:
            findings.append(Finding(
                id="AG-010",
                title="No Rate Limiting on High-Risk Tools",
                severity=Severity.MEDIUM,
                description=(
                    f"Agent '{agent.name}' has {len(high_risk_tools)} high-risk tool(s) "
                    f"with no rate limiting configured. A runaway agent could invoke these "
                    f"tools thousands of times per second."
                ),
                agent_name=agent.name,
                attack_scenario=(
                    "Without rate limits, a compromised or hallucinating agent can: "
                    "execute thousands of commands (DoS), make unlimited API calls (cost explosion), "
                    "or exfiltrate data at maximum throughput. The Hugging Face breach involved "
                    "an estimated 17,600 actions — rate limiting would have triggered detection earlier."
                ),
                blast_radius="Unlimited invocations of high-risk tools at machine speed.",
                owasp_ref=owasp_ref("AG-010"),
                fix_suggestion=(
                    "Add rate limiting:\n"
                    "  → Max N tool calls per minute per tool type\n"
                    "  → Circuit breaker: pause agent if >X calls in Y seconds\n"
                    "  → Alert on anomalous call frequency"
                ),
                source_file=agent.source_file,
            ))

    # AG-026: Ambient authority (elevated privileges)
    ambient_findings = _detect_ambient_authority(agent)
    findings.extend(ambient_findings)

    return findings


def _detect_ambient_authority(agent: Agent) -> list[Finding]:
    """Detect when an agent runs with elevated/ambient privileges.

    Elevated privileges mean a compromise gives the attacker MORE access
    than necessary. Principle of least privilege violations:
    - AutoGen with use_docker=False (code runs as host user)
    - Docker --privileged (container has host-level access)
    - Running as root/admin
    - human_input_mode="NEVER" + code execution (fully autonomous with host access)
    """
    findings = []

    if not agent.source_file:
        return findings

    from pathlib import Path
    try:
        content = Path(agent.source_file).read_text(encoding="utf-8")
    except (FileNotFoundError, PermissionError):
        return findings

    import re
    content_lower = content.lower()

    # Check for AutoGen use_docker=False (code runs directly on host)
    if "use_docker" in content_lower:
        if re.search(r'["\']?use_docker["\']?\s*[:=]\s*(?:False|false)', content):
            findings.append(Finding(
                id="AG-026",
                title="Ambient Authority: Code Execution Without Container Isolation",
                severity=Severity.CRITICAL,
                description=(
                    f"Agent '{agent.name}' has code execution configured with "
                    f"`use_docker: False`. This means generated code runs DIRECTLY "
                    f"on the host machine with the user's full permissions.\n\n"
                    f"A prompt injection can execute arbitrary commands as YOUR user."
                ),
                agent_name=agent.name,
                attack_scenario=(
                    "1. Agent receives prompt injection via user input or tool output\n"
                    "2. Injection instructs agent to generate malicious code\n"
                    "3. Code executes on HOST (not in container) with full permissions\n"
                    "4. Attacker has shell access as the user running the agent"
                ),
                blast_radius="Full host system access. All files, credentials, network.",
                owasp_ref=owasp_ref("AG-026"),
                fix_suggestion=(
                    "Set `use_docker: True` to isolate code execution in containers.\n"
                    "Or use a restricted sandbox (firejail, nsjail, gVisor).\n"
                    "NEVER run agent-generated code directly on the host."
                ),
                source_file=agent.source_file,
            ))

    # Check for Docker --privileged
    if "--privileged" in content:
        findings.append(Finding(
            id="AG-026",
            title="Ambient Authority: Docker Privileged Mode",
            severity=Severity.HIGH,
            description=(
                f"Agent '{agent.name}' configuration uses Docker `--privileged` flag. "
                f"This gives the container FULL access to the host kernel — "
                f"effectively the same as running without a container."
            ),
            agent_name=agent.name,
            attack_scenario=(
                "A privileged container can: mount host filesystems, "
                "access all devices, modify kernel parameters, "
                "and escape to the host trivially."
            ),
            blast_radius="Full host access despite being 'containerized'.",
            owasp_ref=owasp_ref("AG-026"),
            fix_suggestion="Remove --privileged. Use specific --cap-add for needed capabilities only.",
            source_file=agent.source_file,
        ))

    # Check for human_input_mode="NEVER" + code execution (fully autonomous)
    if 'human_input_mode' in content_lower:
        if re.search(r'human_input_mode\s*=\s*["\']NEVER["\']', content):
            has_code_exec = any(
                ToolCapability.EXECUTE_CODE in t.capabilities for t in agent.tools
            )
            if has_code_exec:
                findings.append(Finding(
                    id="AG-026",
                    title="Ambient Authority: Fully Autonomous Code Execution",
                    severity=Severity.HIGH,
                    description=(
                        f"Agent '{agent.name}' has `human_input_mode='NEVER'` AND "
                        f"code execution capability. This means the agent can generate "
                        f"and execute code with ZERO human oversight."
                    ),
                    agent_name=agent.name,
                    attack_scenario=(
                        "The agent operates fully autonomously with code execution. "
                        "Any prompt injection leads directly to code execution with "
                        "no human checkpoint to catch malicious behavior."
                    ),
                    blast_radius="All actions the code executor can perform.",
                    owasp_ref=owasp_ref("AG-026"),
                    fix_suggestion=(
                        "Set human_input_mode='ALWAYS' or 'TERMINATE' for destructive ops.\n"
                        "Or add a code review step before execution."
                    ),
                    source_file=agent.source_file,
                ))

    return findings
