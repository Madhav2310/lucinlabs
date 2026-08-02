"""AG-014: Multi-Agent Delegation Chain Analysis.

Detects security risks in how agents delegate tasks to sub-agents,
including:
- Unrestricted delegation (agent can delegate to any other agent)
- Privilege inheritance (sub-agent inherits parent's full permissions)
- Circular delegation (agent chains that could loop)
- No delegation audit trail (actions taken by sub-agents aren't attributed)

Real-world basis:
- Agents of Chaos (arXiv:2602.20021): Cross-agent propagation of unsafe behavior
  was one of the 11 documented failure modes. One compromised agent "infected"
  others through delegation.
- OWASP Agentic #6: Cascading Failures — errors and unsafe behaviors propagate
  through delegation chains.
- Multi-agent systems where Agent A delegates to Agent B, and B escalates
  privileges by combining A's permissions with its own tools.

This is particularly dangerous because:
1. The delegating agent trusts the sub-agent implicitly
2. The sub-agent may have different (broader) tool access
3. The human user approved Agent A — they didn't approve Agent B
4. Actions by sub-agents may not appear in the audit trail as "delegated"
"""

from lucin.models import Agent, Finding, Severity, Tool, ToolCapability
from lucin.owasp import owasp_ref


def detect_delegation_risks(agents: list[Agent]) -> list[Finding]:
    """Analyze delegation patterns across a SET of agents (not just one).

    This detector looks at relationships BETWEEN agents, not within a single agent.
    It requires multiple agents to be parsed from the same project.
    """
    findings = []

    # Only meaningful if we have multiple agents
    if len(agents) < 2:
        # Still check individual agents for delegation capability without controls
        for agent in agents:
            findings.extend(_check_individual_delegation(agent))
        return findings

    # Multi-agent analysis
    findings.extend(_check_privilege_escalation_via_delegation(agents))
    findings.extend(_check_unrestricted_delegation(agents))
    # NOTE (H4): _check_missing_delegation_audit was a no-op (always returned [])
    # — detecting audit infrastructure needs runtime telemetry, not static
    # analysis — so it is no longer called. Removed rather than left dangling.

    # Individual checks
    for agent in agents:
        findings.extend(_check_individual_delegation(agent))

    return findings


def _check_individual_delegation(agent: Agent) -> list[Finding]:
    """Check a single agent's delegation configuration."""
    findings = []

    if agent.can_spawn_subagents and not agent.has_human_in_loop:
        # Agent can delegate without human oversight
        tool_names = ", ".join(t.name for t in agent.tools[:5])
        findings.append(Finding(
            id="AG-014",
            title="Delegation Without Oversight",
            severity=Severity.MEDIUM,
            description=(
                f"Agent '{agent.name}' can delegate tasks to sub-agents "
                f"without human-in-the-loop approval. Sub-agents may inherit "
                f"permissions or execute actions the user didn't explicitly authorize.\n\n"
                f"This agent has access to: {tool_names}"
            ),
            agent_name=agent.name,
            attack_scenario=(
                "1. User asks Agent A to perform a task\n"
                "2. Agent A delegates part of the task to Agent B\n"
                "3. Agent B has different/broader tool access than A\n"
                "4. Agent B performs actions the user never authorized\n"
                "5. User's audit trail shows A's actions but not B's"
            ),
            blast_radius=(
                "All actions taken by sub-agents execute with delegated authority. "
                "The blast radius expands beyond the original agent's intended scope."
            ),
            owasp_ref=owasp_ref("AG-014"),
            fix_suggestion=(
                "1. Require human approval before delegation:\n"
                "   → LangGraph: interrupt_before on delegation nodes\n"
                "2. Restrict sub-agent permissions to subset of parent's:\n"
                "   → Sub-agents should NEVER have more tools than the delegating agent\n"
                "3. Maintain delegation audit trail:\n"
                "   → Log: who delegated to whom, what was the task, what actions were taken\n"
                "4. Set delegation depth limit:\n"
                "   → Maximum 2-3 levels of delegation to prevent unbounded chains"
            ),
            source_file=agent.source_file,
        ))

    return findings


def _check_privilege_escalation_via_delegation(agents: list[Agent]) -> list[Finding]:
    """Check if delegation chains could escalate privileges.

    If Agent A (with tools [read]) delegates to Agent B (with tools [read, write, exec]),
    then B effectively grants A access to write and exec through delegation.
    """
    findings = []

    delegating_agents = [a for a in agents if a.can_spawn_subagents]
    if not delegating_agents:
        return findings

    for delegator in delegating_agents:
        delegator_caps = set()
        for tool in delegator.tools:
            delegator_caps.update(tool.capabilities)

        # Check other agents in the system for broader capabilities
        for target in agents:
            if target.name == delegator.name:
                continue

            target_caps = set()
            for tool in target.tools:
                target_caps.update(tool.capabilities)

            # If target has capabilities the delegator doesn't have = escalation risk
            escalation_caps = target_caps - delegator_caps
            if escalation_caps and ToolCapability.EXECUTE_CODE in escalation_caps:
                findings.append(Finding(
                    id="AG-014",
                    title="Privilege Escalation via Delegation",
                    severity=Severity.HIGH,
                    description=(
                        f"Agent '{delegator.name}' can delegate to '{target.name}', "
                        f"which has capabilities that '{delegator.name}' lacks: "
                        f"{[c.value for c in escalation_caps]}.\n\n"
                        f"Through delegation, '{delegator.name}' can indirectly access "
                        f"capabilities it was never directly granted."
                    ),
                    agent_name=delegator.name,
                    attack_scenario=(
                        f"1. User interacts with '{delegator.name}' (limited permissions)\n"
                        f"2. Attacker crafts input that triggers delegation to '{target.name}'\n"
                        f"3. '{target.name}' has {[c.value for c in escalation_caps]} — broader access\n"
                        f"4. Attack executes with escalated privileges via the delegation chain\n"
                        f"5. User audit trail shows '{delegator.name}' but not the escalation"
                    ),
                    blast_radius=(
                        f"All capabilities of '{target.name}': "
                        f"{[c.value for c in target_caps]}"
                    ),
                    owasp_ref=owasp_ref("AG-014"),
                    fix_suggestion=(
                        f"1. Ensure sub-agents have EQUAL OR FEWER permissions than delegators\n"
                        f"2. Add delegation policy: '{delegator.name}' should only delegate "
                        f"to agents with a subset of its own capabilities\n"
                        f"3. Implement capability-based delegation tokens that limit what "
                        f"the sub-agent can do on behalf of the delegator"
                    ),
                    source_file=delegator.source_file,
                ))

    return findings


def _check_unrestricted_delegation(agents: list[Agent]) -> list[Finding]:
    """Check for agents that can delegate to ANY other agent without restrictions."""
    findings = []

    delegating_agents = [a for a in agents if a.can_spawn_subagents]

    # If multiple agents can all delegate to each other = potential circular delegation
    if len(delegating_agents) >= 2:
        names = [a.name for a in delegating_agents]
        findings.append(Finding(
            id="AG-014",
            title="Mutual Delegation Risk (Potential Circular Chains)",
            severity=Severity.MEDIUM,
            description=(
                f"Multiple agents can delegate to each other: {names}. "
                f"This creates potential for circular delegation chains where "
                f"Agent A delegates to B, B delegates to C, C delegates back to A — "
                f"causing infinite loops or resource exhaustion."
            ),
            agent_name=names[0],
            attack_scenario=(
                "1. Agent A receives a complex task and delegates to Agent B\n"
                "2. Agent B can't handle it and delegates back to A (or to C→A)\n"
                "3. This creates an infinite delegation loop\n"
                "4. Resource exhaustion: tokens, compute, API calls accumulate\n"
                "5. No termination condition exists"
            ),
            blast_radius="Potential infinite resource consumption via delegation loops.",
            owasp_ref=owasp_ref("AG-014"),
            fix_suggestion=(
                "1. Set maximum delegation depth (e.g., max 3 hops)\n"
                "2. Track delegation history and prevent cycles\n"
                "3. Implement delegation budget (max tokens/cost per chain)\n"
                "4. Require explicit delegation targets (not 'any available agent')"
            ),
            source_file=delegating_agents[0].source_file,
        ))

    return findings


