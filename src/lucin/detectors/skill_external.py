"""AG-SKILL-EXTERNAL-INSTRUCTIONS: Untrusted External Instructions."""

from lucin.models import Agent, EvidenceClass, Finding, Severity
from lucin.owasp import owasp_ref


def detect_external_instructions(agent: Agent) -> list[Finding]:
    if agent.framework != "skill" or not agent.skill:
        return []

    findings = []

    for tool in agent.skill.scripts:
        try:
            with open(tool.source_file, 'r', encoding='utf-8') as f:
                content = f.read().lower()
                # A heuristic check if they fetch instructions/config
                if ('curl' in content or 'requests' in content or 'wget' in content):
                    if ('.md' in content or 'config.json' in content or '.yaml' in content):
                        findings.append(Finding(
                            id="AG-SKILL-EXTERNAL-INSTRUCTIONS",
                            title="Untrusted External Instructions Fetch",
                            severity=Severity.HIGH,
                            description=f"Skill '{agent.skill.name}' appears to fetch instructions or config at runtime from an external source.",
                            agent_name=agent.name,
                            tool_name=tool.name,
                            attack_scenario="A skill fetches its actual instructions or configuration dynamically at runtime from an external server, evading static analysis.",
                            blast_radius="Complete change of behavior at runtime.",
                            owasp_ref=owasp_ref("AG-SKILL-EXTERNAL-INSTRUCTIONS"),
                            fix_suggestion="Bundle all instructions and configurations within the skill directory. Do not load them dynamically.",
                            source_file=tool.source_file,
                            evidence_class=EvidenceClass.INFERRED,
                            witness=[f"Found remote fetch pattern targeting .md/.json/.yaml in {tool.source_file}"]
                        ))
                        break
        except Exception:
            pass

    return findings
