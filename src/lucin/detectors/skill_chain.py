"""AG-SKILL-CHAIN: Cross-artifact chain composition.

Redesigned per PHASE_6_PLAN.md §5.3/§5.2.4: a differential run against
NVIDIA/SkillSpector over 337 real skills found the previous version (which
fired on "N dangerous imports co-occur in the file," gated by manifest
declaration) produced 0 differentiated findings — every skill it flagged,
SkillSpector also flagged, usually with far more depth; SkillSpector caught
128 skills this detector missed entirely.

Two changes:
1. **Severity now comes from a PROVEN flow, not from the manifest.**
   `parsers/body_inspector.py::source_sink_taint` runs the same fixpoint
   taint algorithm the main scanner's own detectors use, seeded for
   standalone scripts (source calls, not tool-function parameters) — modeled
   on NVIDIA/SkillSpector's taint analyzer (Apache-2.0) but reusing this
   project's own sink tables. A real source-to-sink flow is CRITICAL and
   WITNESSED (a line a reader can open). §2.3/§5.3 established that
   declaration is attacker-controlled and cannot discriminate malice — so
   whether the manifest says anything no longer changes this severity at all.
2. Bare capability co-occurrence with no proven flow (the old behavior) is
   kept as a much weaker, INFO-only, INFERRED signal — useful context, not a
   verdict.
"""
import ast
from pathlib import Path

from lucin.models import Agent, EvidenceClass, Finding, Severity, SkillCapability
from lucin.owasp import owasp_ref
from lucin.parsers.body_inspector import build_import_alias_map, source_sink_taint

DANGEROUS_CAPS = {
    SkillCapability.REMOTE_FETCH,
    SkillCapability.DECODE,
    SkillCapability.DESERIALIZE,
    SkillCapability.EXEC,
    SkillCapability.EGRESS,
    SkillCapability.CREDENTIAL_READ,
}


def _python_flows(skill) -> list[tuple[str, object]]:
    """Real source->sink flows for every bundled `.py` script."""
    results = []
    for tool in skill.scripts:
        if not tool.source_file.endswith(".py"):
            continue
        try:
            content = Path(tool.source_file).read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(content)
        except Exception:
            continue
        aliases = build_import_alias_map(tree)
        for flow in source_sink_taint(tree, aliases):
            results.append((tool.source_file, flow))
    return results


def detect_skill_chain(agent: Agent) -> list[Finding]:
    if agent.framework != "skill" or not agent.skill:
        return []
    skill = agent.skill

    # Tier 1: a PROVEN flow. This is the flagship signal — CRITICAL, WITNESSED,
    # independent of what (if anything) the manifest declares.
    flows = _python_flows(skill)
    if flows:
        witnesses = [
            f"{src_file}:{flow.lineno} {flow.source_call} → {flow.sink_call} ({flow.sink_type})"
            for src_file, flow in flows[:5]
        ]
        first_file, first_flow = flows[0]
        return [Finding(
            id="AG-SKILL-CHAIN",
            title="Proven Data Flow to a Dangerous Sink",
            severity=Severity.CRITICAL,
            description=(
                f"Skill '{skill.name}' has {len(flows)} confirmed flow(s) where an "
                f"untrusted/external source (remote fetch, credential/env read, file "
                f"read, or user input) reaches a dangerous sink (code execution, "
                f"deserialization, network egress, or file write)."
            ),
            agent_name=agent.name,
            attack_scenario=(
                "An attacker-influenced value — fetched remotely, read from a "
                "credential/env var, or supplied by the user — flows directly into "
                "a dangerous operation (exec, deserialize, network send, or write) "
                "without an intervening check."
            ),
            blast_radius="Depends on the sink: arbitrary code execution, credential exfiltration, or file tampering.",
            owasp_ref=owasp_ref("AG-SKILL-CHAIN"),
            fix_suggestion="Validate/sanitize the tainted value before it reaches the sink, or remove the flow entirely.",
            source_file=first_file,
            source_line=first_flow.lineno,
            evidence_class=EvidenceClass.WITNESSED,
            witness=witnesses,
        )]

    # Tier 2: capability co-occurrence, no proven flow — a much weaker signal.
    observed = set(skill.observed_capabilities)
    chain = observed.intersection(DANGEROUS_CAPS)
    if len(chain) >= 2:
        return [Finding(
            id="AG-SKILL-CHAIN",
            title="Co-occurring High-Risk Capabilities (No Proven Flow)",
            severity=Severity.INFO,
            description=(
                f"Skill '{skill.name}' uses high-risk primitives "
                f"{[c.value for c in chain]}, but static analysis could not prove a "
                f"direct source-to-sink flow between them — they may be unconnected "
                f"legitimate uses."
            ),
            agent_name=agent.name,
            attack_scenario="These capabilities may compose into an attack chain at runtime in a way static analysis cannot confirm.",
            blast_radius="Unconfirmed — depends on whether these primitives are actually connected.",
            owasp_ref=owasp_ref("AG-SKILL-CHAIN"),
            fix_suggestion="Review whether these capabilities are connected; if so, consider isolating them.",
            source_file=skill.source_file,
            evidence_class=EvidenceClass.INFERRED,
            witness=[f"Observed capabilities: {[c.value for c in chain]}"],
        )]

    return []
