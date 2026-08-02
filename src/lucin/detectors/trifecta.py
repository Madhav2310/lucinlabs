"""AG-TRIFECTA: Information-flow exfiltration path detector.

Detects the lethal trifecta (Blueprint §3.3):
  (T) untrusted source has control influence over an egress sink
  (S) internal/secret source has data path to that egress sink
  (E) the sink crosses the trust boundary outward
  (¬D) no declassifier/endorser mediates either path

This is the IFC-formal successor to AG-002 (Data Exfiltration Path).

Key difference from AG-002:
- AG-002: simple capability-set intersection (READ ∩ NETWORK).
  Fast, catches obvious cases, no path context.
- AG-TRIFECTA: labeled graph reachability over the AIFG.
  Emits a proof-witness path (the actual data/control flow chain),
  names the minimal set of tool restrictions that provably fix it,
  and distinguishes control influence from data flow.

Both detectors coexist in Phase 1. As the AIFG edge construction
becomes more precise (Phase 1b taint engine), AG-TRIFECTA will
progressively subsume AG-002. Until then they are complementary.
"""

from lucin.models import Agent, Finding, Severity
from lucin.aifg import build_aifg, query_trifecta, min_tool_cut, TrifectaFinding
from lucin.owasp import owasp_ref


def detect_trifecta(agent: Agent) -> list[Finding]:
    """Run the AIFG trifecta query and emit findings with proof-witnesses."""
    g = build_aifg(agent)
    trifecta_findings = query_trifecta(g)

    if not trifecta_findings:
        return []

    # Compute min-cut once for the full set of trifecta sinks
    untrusted_ctrl = [
        nid for nid, n in g.nodes.items()
        if n.label.is_untrusted() and not n.is_llm
    ]
    egress_sinks = [
        nid for nid, n in g.nodes.items()
        if n.is_egress
    ]
    removable = {t.name for t in agent.tools}
    cut = min_tool_cut(g, untrusted_ctrl, egress_sinks, removable)
    cut_str = (
        f"Minimal fix (provably breaks all exfil paths):\n"
        + "\n".join(f"  → Restrict or gate tool '{t}'" for t in sorted(cut))
        if cut else
        "No removable tool identified — review agent architecture."
    )

    findings = []
    for tf in trifecta_findings:
        findings.append(_make_finding(agent, tf, cut_str))

    return findings


def _make_finding(agent: Agent, tf: TrifectaFinding, cut_str: str) -> Finding:
    ctrl_chain = " → ".join(tf.control_path)
    data_chain = " → ".join(tf.data_path)

    return Finding(
        id="AG-TRIFECTA",
        title=f"Information-Flow Exfiltration Path → '{tf.egress_sink}'",
        severity=Severity.CRITICAL,
        description=(
            f"Lethal trifecta detected: untrusted input can control the egress "
            f"tool '{tf.egress_sink}' while internal/sensitive data flows to it, "
            f"creating a provable exfiltration path.\n\n"
            f"Control path (attacker steers the sink):\n  {ctrl_chain}\n\n"
            f"Data path (sensitive data reaches the payload):\n  {data_chain}"
        ),
        agent_name=agent.name,
        attack_scenario=(
            f"1. Attacker injects instructions via an untrusted input "
            f"(e.g. web content, email, tool return from '{tf.control_source}')\n"
            f"2. Injected instructions cause the LLM to invoke '{tf.egress_sink}'\n"
            f"3. The payload carries data from '{tf.data_source}' "
            f"(internal/sensitive) to an external destination\n"
            f"This is the exact attack pattern of EchoLeak (CVE-2025-32711) "
            f"and the GitHub-MCP toxic-agent incident."
        ),
        blast_radius=(
            f"All data accessible via '{tf.data_source}' can be exfiltrated "
            f"through '{tf.egress_sink}' without user awareness."
        ),
        owasp_ref=owasp_ref("AG-TRIFECTA"),
        fix_suggestion=(
            f"{cut_str}\n\n"
            f"Architectural remediation (Blueprint §6.1 — CaMeL/Fides pattern):\n"
            f"  1. Enforce IFC labels at the tool boundary: block any call to\n"
            f"     '{tf.egress_sink}' where arguments carry INTERNAL/SECRET data\n"
            f"     AND the call was triggered by UNTRUSTED input.\n"
            f"  2. Add an explicit declassification allowlist for legitimate\n"
            f"     '{tf.egress_sink}' calls (e.g. user-initiated sends only).\n"
            f"  3. Route egress through an allowlist of known-safe destinations."
        ),
        source_file=agent.source_file,
        witness=[
            f"control: {' → '.join(tf.control_path)}",
            f"data:    {' → '.join(tf.data_path)}",
        ],
    )
