"""AG-SKILL-MANIFEST-GAP: Capability declaration reconciliation.

Always INFO — a disclosure report, not a verdict (§8.4 channel 3). Uses
`skill_declaration.reconcile`, which fixed three bugs in the prior version:
wildcard/unscoped declarations no longer launder every other capability (they
get their own line here instead), a listed dependency no longer counts as
"declaring" the capability it implies, and the `compatibility` field is
actually checked now (it previously sat unused despite the fix_suggestion
text telling authors to use it).
"""
from lucin.detectors.skill_declaration import reconcile
from lucin.models import Agent, EvidenceClass, Finding, Severity
from lucin.owasp import owasp_ref


def detect_skill_manifest_gap(agent: Agent) -> list[Finding]:
    if agent.framework != "skill" or not agent.skill:
        return []

    skill = agent.skill
    compat_text = str(skill.frontmatter.get("compatibility", ""))
    report = reconcile(skill.observed_capabilities, skill.declared_capabilities, compat_text)

    findings = []

    if report.has_wildcard:
        findings.append(Finding(
            id="AG-SKILL-MANIFEST-GAP",
            title="Unscoped Capability Declaration",
            severity=Severity.INFO,
            description=(
                f"Skill '{skill.name}' declares unscoped access ({report.wildcard_tokens}) "
                f"in `allowed-tools`. An unscoped grant (bare `Bash`, `*`, `all`) covers "
                f"every capability at once, which defeats the purpose of per-capability "
                f"review — it is equivalent to declaring nothing specific."
            ),
            agent_name=agent.name,
            attack_scenario="A reviewer sees a manifest entry and assumes some scoping was applied, when none was.",
            blast_radius="N/A — a disclosure/posture note, not a proven capability.",
            owasp_ref=owasp_ref("AG-SKILL-MANIFEST-GAP"),
            fix_suggestion="Use scoped syntax instead, e.g. `Bash(git:*)` `Bash(curl:*)` rather than bare `Bash`.",
            source_file=skill.source_file,
            evidence_class=EvidenceClass.POSTURE,
        ))

    if report.undeclared:
        findings.append(Finding(
            id="AG-SKILL-MANIFEST-GAP",
            title="Undeclared Capabilities (Capability Disclosure Report)",
            severity=Severity.INFO,  # Report, not verdict
            description=(
                f"Skill '{skill.name}' uses capabilities not declared in `allowed-tools` "
                f"or `compatibility`: {[c.value for c in report.undeclared]}."
            ),
            agent_name=agent.name,
            attack_scenario="Undeclared capabilities hide actual behavior from humans and security teams.",
            blast_radius="Depends on the capability.",
            owasp_ref=owasp_ref("AG-SKILL-MANIFEST-GAP"),
            fix_suggestion="Declare these capabilities via `allowed-tools` (precise) or `compatibility` (coarse).",
            source_file=skill.source_file,
            evidence_class=EvidenceClass.POSTURE,
        ))

    return findings
