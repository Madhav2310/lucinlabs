"""Security detectors for agent configurations."""

from lucin.detectors.agent_server import detect_agent_server
from lucin.detectors.compositional_risk import detect_compositional_risk
from lucin.detectors.context_overflow import detect_context_overflow
from lucin.detectors.cross_origin import detect_cross_origin
from lucin.detectors.data_exfiltration import detect_data_exfiltration
from lucin.detectors.delegation import detect_delegation_risks
from lucin.detectors.docker_exec import detect_docker_exec
from lucin.detectors.encoding_detection import detect_encoding_obfuscation
from lucin.detectors.framework_pin import detect_framework_pin
from lucin.detectors.insecure_deserialization import detect_insecure_deserialization
from lucin.detectors.mcp_auth import detect_unauthenticated_mcp
from lucin.detectors.missing_controls import detect_missing_controls
from lucin.detectors.no_telemetry import detect_no_telemetry
from lucin.detectors.overprivilege import detect_dangerous_combinations
from lucin.detectors.path_traversal import detect_path_traversal
from lucin.detectors.prompt_leakage import detect_prompt_leakage
from lucin.detectors.rag_sanitize import detect_rag_no_sanitize
from lucin.detectors.scope_violation import detect_scope_violations
from lucin.detectors.secrets import detect_secrets
from lucin.detectors.secrets_fallback import detect_secrets_fallback
from lucin.detectors.self_modification import detect_self_modification
from lucin.detectors.shell_access import detect_unrestricted_shell
from lucin.detectors.sql_injection import detect_sql_injection
from lucin.detectors.ssrf import detect_ssrf
from lucin.detectors.supply_chain import detect_supply_chain
from lucin.detectors.tool_poisoning import detect_tool_poisoning
from lucin.detectors.tool_shadowing import detect_tool_shadowing
from lucin.detectors.trifecta import detect_trifecta
from lucin.models import Agent, Finding, Severity
from lucin.rule_docs import cwes_for

# ---------------------------------------------------------------------------
# The DETECTOR REGISTRY — the single source of truth for "what runs".
#
# ScanMetadata.detection_rules_active is derived from ACTIVE_DETECTOR_COUNT
# (H4: no hardcoded 23/32/55 that drifts from reality). A detector appears here
# iff it is actually executed by run_all_detectors AND can emit findings — so
# the transparency count can never over-state coverage.
#
# NOT registered (intentional, documented):
#   - detect_path_traversal: sound + unit-tested, but the benign corpus contains
#     byte-identical benign counterparts of every path-traversal shape, so
#     registering it breaks the 0% FP guarantee. Gated off (precision > recall).
#   - detect_memory_poisoning (AG-013): the entry point currently `return []`
#     (disabled until rebuilt with a real FP measurement). A registered detector
#     that can never fire is a no-op that inflates the count — so it is NOT in
#     the registry. Re-add it here once it emits findings again.
# ---------------------------------------------------------------------------

# Per-agent detectors (analyze each agent independently).
PER_AGENT_DETECTORS = [
    detect_unrestricted_shell,
    detect_data_exfiltration,
    detect_unauthenticated_mcp,
    detect_dangerous_combinations,
    detect_secrets,
    detect_tool_poisoning,
    detect_missing_controls,
    detect_supply_chain,
    detect_self_modification,
    detect_context_overflow,
    detect_encoding_obfuscation,
    detect_scope_violations,
    detect_cross_origin,
    detect_compositional_risk,
    detect_tool_shadowing,
    detect_prompt_leakage,
    detect_no_telemetry,
    detect_trifecta,
    detect_sql_injection,
    detect_agent_server,
    detect_secrets_fallback,
    detect_framework_pin,
    detect_docker_exec,
    detect_rag_no_sanitize,
    detect_ssrf,
    detect_insecure_deserialization,
]

# Cross-agent detectors (analyze relationships between agents).
CROSS_AGENT_DETECTORS = [
    detect_delegation_risks,
]

# Total number of detectors that actually run (transparency source of truth).
ACTIVE_DETECTOR_COUNT = len(PER_AGENT_DETECTORS) + len(CROSS_AGENT_DETECTORS)


def run_all_detectors(agents: list[Agent],
                      diagnostics: list[str] | None = None) -> list[Finding]:
    """Run all detection rules against parsed agents.

    Architecture:
    1. Per-agent detectors (analyze each agent independently)
    2. Cross-agent detectors (analyze relationships between agents)

    CRASH-ISOLATION (E1): every detector invocation is wrapped in try/except.
    A detector that raises on one malformed agent must NOT abort the whole scan
    (a crashed scan has 0% recall on that repo — a security failure, not just a
    bug). Errors are appended to `diagnostics` (if provided) and scanning
    continues with the remaining detectors/agents.

    DE-DUPLICATION (E7): subsumed exfiltration findings (AG-002 / AG-COMP) that
    describe the same read→egress root cause as a more specific AG-TRIFECTA
    finding are collapsed into a single primary finding with linked context.
    """
    findings: list[Finding] = []

    # Per-agent detectors
    for agent in agents:
        for detector in PER_AGENT_DETECTORS:
            try:
                findings.extend(detector(agent))
            except Exception as exc:  # noqa: BLE001 — crash-isolation is deliberate
                _record(diagnostics, detector, exc, agent=agent)

    # Cross-agent detectors (analyze relationships between agents)
    for detector in CROSS_AGENT_DETECTORS:
        try:
            findings.extend(detector(agents))
        except Exception as exc:  # noqa: BLE001
            _record(diagnostics, detector, exc)

    findings = _require_evidence_on_unproven_agents(findings, agents, diagnostics)
    findings = _bound_severity_by_evidence(findings, diagnostics)
    findings = _dedupe_subsumed_exfil(findings)
    findings = _dedupe_identical_location(findings)
    return _finalize(findings)


# Severity order for presentation. Worst first — a user reads top-down.
_SEV_RANK = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
             Severity.LOW: 3, Severity.INFO: 4}


def _dedupe_identical_location(findings: list[Finding]) -> list[Finding]:
    """Collapse findings that name the SAME rule at the SAME code location.

    A file-level detector that inspects sibling files (AG-CORS/AG-NOAUTH scan every
    `*.py` next to an agent, because `server.py` usually sits beside `agent.py`) re-emits
    the same weakness once per agent that shares the directory. Measured on a real repo:
    `lucin scan src/` on h2ogpt produced **7 identical AG-CORS findings**, all pointing at
    the same `function_server.py` line -- one weakness, seven rows.

    That is an effective-false-positive generator even though every row is technically
    true: a user cannot tell seven problems from one, and a scanner that inflates its own
    count is the thing this project criticises in other people's tools.

    Keyed on (rule id, source_file, source_line, title). The title is load-bearing, not
    decoration: one line can carry two genuinely different weaknesses under the same rule --
    `secret_key = "<48 random chars>"` fires AG-007 twice, once as an AWS-key pattern match
    and once on Shannon entropy, and collapsing those loses a real detection. A regression
    test caught exactly that when this function keyed on location alone.

    The retained copy is the one with the most evidence (longest witness), so deduplication
    never costs explanation.
    """
    best: dict[tuple, Finding] = {}
    order: list[tuple] = []
    for f in findings:
        # Only collapse when we have a concrete location to key on. Findings with no
        # source_file are agent-scoped, not location-scoped, and must not be merged.
        if not f.source_file:
            key = ("__unkeyed__", id(f))
        else:
            key = (f.id, f.source_file, f.source_line, f.title)
        if key not in best:
            best[key] = f
            order.append(key)
            continue
        incumbent = best[key]
        if len(f.witness or ()) > len(incumbent.witness or ()):
            best[key] = f
    return [best[k] for k in order]


def _finalize(findings: list[Finding]) -> list[Finding]:
    """Attach CWEs and impose a DETERMINISTIC, useful order. The one exit point.

    Determinism
    -----------
    Findings were emitted in nondeterministic order: detectors iterate sets of
    capabilities and tool names, and Python seeds string hashing per process, so the
    same scan produced the same findings in a different sequence on every run
    (verified: 4 runs of one repo gave 4 different orderings with identical content).
    That breaks diffing, baselining, caching, and any consumer that matches findings
    positionally — a third-party benchmark run hit exactly this.

    Fixing it *here* rather than in each detector is deliberate: this is the single
    place every finding passes through, so no future detector can reintroduce the bug
    by using a set internally — which they legitimately do, and should.

    The sort key must be TOTAL. Python's sort is stable, so any tie would silently
    fall back to the nondeterministic input order and the bug would survive in exactly
    the cases that are hardest to notice.

    Ordering is also a UX fix: the previous order was detector-registry order, which
    means nothing to a reader. Worst-first, then by location, is what someone triaging
    actually wants.
    """
    for f in findings:
        if not f.cwe:
            f.cwe = cwes_for(f.id)
    findings.sort(key=lambda f: (
        _SEV_RANK.get(f.severity, 9),
        f.source_file or "",
        f.source_line or 0,
        f.id or "",
        f.tool_name or "",
        f.agent_name or "",
        f.title or "",
        "|".join(f.witness or ()),      # last resort, guarantees totality
    ))
    return findings


# Severity ceiling for a finding that offers the reader NO way to check it.
_NO_EVIDENCE_CEILING = Severity.MEDIUM


def _bound_severity_by_evidence(findings: list[Finding],
                                diagnostics: list[str] | None = None) -> list[Finding]:
    """A finding nobody can check must not be CRITICAL or HIGH.

    "Evidence" is deliberately generous: a witness string OR a `source_line` the
    reader can open. What it excludes is the posture/composition family
    (AG-006 no-HITL, AG-028 no-telemetry, AG-COMP, AG-002, AG-005a/b, AG-NOAUTH),
    which asserts something about an agent's capability *set* — no line, no path,
    nothing to look at.

    Measured on the 81-repo population (2026-07-30), on the hand-adjudicated
    sample:
        with a witness or a line : 7 TP /  7 FP = 50% precision
        with neither             : 1 TP /  8 FP = 11% precision
                                   ...and 21 of the 23 findings that could not be
                                   adjudicated AT ALL live in that second bucket.
    So this is not cosmetic re-labelling: it makes every remaining HIGH/CRITICAL
    finding something a human can actually verify, which is the whole product
    claim. 114 of 209 findings (55%) are capped.

    HONEST NOTE — this interacts with two published metrics and we say so in
    docs/methodology.md: (a) the benign-corpus FP number counts CRITICAL/HIGH
    only, so capping makes that number *easier* to hold; (b) broad-population
    precision is also HIGH/CRIT-scoped, so part of the improvement is re-grading
    rather than removal. The findings are still REPORTED (at MEDIUM) — recall is
    unaffected because detection is severity-independent.
    """
    capped = 0
    for f in findings:
        if f.severity in (Severity.CRITICAL, Severity.HIGH):
            has_evidence = bool(f.witness) or (f.source_line or 0) > 0
            if not has_evidence:
                f.severity = _NO_EVIDENCE_CEILING
                capped += 1
    if capped and diagnostics is not None:
        diagnostics.append(
            f"capped {capped} finding(s) to {_NO_EVIDENCE_CEILING.value}: "
            "no witness and no source line (unverifiable posture assertion)"
        )
    return findings


def _require_evidence_on_unproven_agents(
    findings: list[Finding], agents: list[Agent],
    diagnostics: list[str] | None = None,
) -> list[Finding]:
    """Drop witness-less findings on files we cannot show are agents at all.

    The generic parser is deliberately aggressive (a function NAMED `execute` or
    `query` is enough to call a file an "agent"), which is right for recall but
    means build scripts, benchmark harnesses, pydantic schema modules,
    prompt-string files and `fake_tools/` also get scanned as agents. On those
    files the capability-composition detectors (AG-006 / AG-028 / AG-COMP /
    AG-002 / AG-005a/b / AG-NOAUTH) fire with **no line and no witness**, i.e. no
    evidence a reader could check.

    Measured across 81 real agent repos (2026-07-30): witness-less findings scored
    **3 TP / 28 FP (9.7% precision) with 38 of 100 unadjudicable** — two careful
    reviewers could not even agree whether they were real. If we cannot produce an
    evidence path, we have not earned a HIGH/CRITICAL finding.

    The rule is narrow on purpose:
      * only for agents with NO `agent_evidence` (no @tool, Tool base class, LLM
        client, tool registry, MCP config or agent constructor), AND
      * only for findings carrying NO witness.
    A witness-backed finding (AG-001 body-confirmed, AG-SQL taint path,
    AG-TRIFECTA, AG-CORS `allow_origins=["*"]`, AG-DOCKER, AG-SSRF) is kept
    everywhere — it stands on its own evidence. Real agents keep their posture
    findings untouched.
    """
    # ONLY the generic parser is aggressive enough to need this, and it is the only
    # one that computes `agent_evidence`. Framework parsers (langchain/crewai/
    # autogen/mcp/swarm/...) match on a framework import, so they are evidence-
    # backed by construction — treating their empty (never-computed) evidence list
    # as "no evidence" wrongly suppressed real MCP/LangChain findings and dropped
    # recall 76% -> 72% with 30 failing tests. Absence of assessment is not
    # absence of evidence.
    unproven = {a.name for a in agents
                if a.framework == "generic" and not a.is_evidence_backed}
    if not unproven:
        return findings
    kept, dropped = [], 0
    for f in findings:
        if f.agent_name in unproven and not f.witness:
            dropped += 1
            continue
        kept.append(f)
    if dropped and diagnostics is not None:
        diagnostics.append(
            f"suppressed {dropped} witness-less finding(s) on "
            f"{len(unproven)} file(s) with no agent evidence"
        )
    return kept


def _record(diagnostics: list[str] | None, detector, exc: Exception,
            agent: Agent | None = None) -> None:
    """Append a crash diagnostic (best-effort; never itself raises)."""
    if diagnostics is None:
        return
    name = getattr(detector, "__name__", repr(detector))
    where = f" on agent '{agent.name}'" if agent is not None else ""
    diagnostics.append(f"detector {name}{where} raised {type(exc).__name__}: {exc}")


# Ranking for the exfiltration finding family (E7). Higher = more specific.
# AG-TRIFECTA carries an untrusted→egress proof-witness (the most precise);
# AG-002 is the read∩network capability path; the AG-COMP "Lateral Movement"
# composition is the least specific (read-count + network heuristic). When >1
# fire on the SAME agent's read→egress root cause, we keep the most specific and
# link the rest instead of emitting 2–3 overlapping CRITICAL/HIGH findings.
_EXFIL_RANK = {"AG-TRIFECTA": 3, "AG-002": 2, "AG-COMP-LATERAL": 1}


def _exfil_key(f: Finding) -> str | None:
    if f.id == "AG-TRIFECTA":
        return "AG-TRIFECTA"
    if f.id == "AG-002":
        return "AG-002"
    # Only the "Lateral Movement" AG-COMP composition overlaps the exfil root
    # cause. The "Persistence" composition (write+memory) is a DISTINCT risk and
    # must never be suppressed by an exfil finding.
    if f.id == "AG-COMP" and "Lateral Movement" in f.title:
        return "AG-COMP-LATERAL"
    return None


def _dedupe_subsumed_exfil(findings: list[Finding]) -> list[Finding]:
    """Collapse overlapping exfiltration findings per agent (E7).

    For each agent, if two or more of {AG-TRIFECTA, AG-002, AG-COMP-Lateral}
    fire, keep only the most specific one and append a "Subsumes" note naming the
    linked (suppressed) findings. All non-exfil findings pass through untouched.
    """
    # Index exfil-family findings per agent; find the winner (most specific).
    winners: dict[str, Finding] = {}      # agent_name -> kept finding
    for f in findings:
        key = _exfil_key(f)
        if key is None:
            continue
        rank = _EXFIL_RANK[key]
        cur = winners.get(f.agent_name)
        if cur is None or rank > _EXFIL_RANK[_exfil_key(cur)]:
            winners[f.agent_name] = f

    # Collect the titles being subsumed, per agent, to annotate the winner.
    subsumed: dict[str, list[str]] = {}
    for f in findings:
        key = _exfil_key(f)
        if key is None:
            continue
        winner = winners.get(f.agent_name)
        if winner is not None and f is not winner:
            subsumed.setdefault(f.agent_name, []).append(f"{f.id} ({f.title})")

    out: list[Finding] = []
    for f in findings:
        key = _exfil_key(f)
        if key is None:
            out.append(f)
            continue
        winner = winners.get(f.agent_name)
        if f is winner:
            links = subsumed.get(f.agent_name)
            if links:
                f = f.model_copy(deep=True)
                f.description += (
                    "\n\nSubsumes (same read→egress root cause, linked for context): "
                    + "; ".join(sorted(set(links)))
                )
            out.append(f)
        # else: subsumed — drop it (its context now lives on the winner)
    return out
