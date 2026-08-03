"""A witness-less finding is not reported on a file we can't show is an agent.

The generic parser is deliberately aggressive — a function merely NAMED `execute`
or `query` makes a file an "agent" — which is right for recall but also drags in
build scripts, benchmark harnesses, pydantic-schema modules, prompt-string files
and `fake_tools/`. On those files the capability-composition detectors fire with
no line and no witness.

Measured across 81 real agent repos (2026-07-30): witness-less findings scored
3 TP / 28 FP (9.7% precision) with 38 of 100 unadjudicable — two careful readers
could not agree whether they were real. Requiring either agent evidence or a
witness removed 71% of false positives (37/52) while losing 0 of 8 true
positives; total HIGH/CRIT on the population fell 429 -> 209.
"""
from lucin.detectors import _require_evidence_on_unproven_agents as gate
from lucin.detectors import run_all_detectors
from lucin.models import Agent, Finding, Severity, Tool, ToolCapability


def _f(agent: str, fid: str, witness: list[str] | None = None) -> Finding:
    return Finding(id=fid, title="t", severity=Severity.HIGH, description="d",
                   agent_name=agent, witness=witness or [])


def test_witnessless_finding_suppressed_on_unproven_generic_agent():
    a = Agent(name="utils", framework="generic", agent_evidence=[])
    out = gate([_f("utils", "AG-006"), _f("utils", "AG-028")], [a])
    assert out == [], "no agent evidence + no witness => no finding"


def test_witness_backed_finding_survives_everywhere():
    """Evidence stands on its own — AG-CORS/AG-SQL/AG-TRIFECTA are never dropped."""
    a = Agent(name="utils", framework="generic", agent_evidence=[])
    out = gate([_f("utils", "AG-CORS", ['allow_origins=["*"] in app.py'])], [a])
    assert len(out) == 1 and out[0].id == "AG-CORS"


def test_real_agent_keeps_its_posture_findings():
    a = Agent(name="bot", framework="generic", agent_evidence=["@tool decorator"])
    out = gate([_f("bot", "AG-006"), _f("bot", "AG-028")], [a])
    assert len(out) == 2, "an evidence-backed agent keeps composition findings"


def test_framework_parsed_agents_are_never_gated():
    """Regression: `agent_evidence` is only computed by the generic parser.

    Treating a framework parser's empty (never-computed) list as "no evidence"
    suppressed real MCP/LangChain findings — recall 76% -> 72%, 30 tests failing.
    Absence of assessment is not absence of evidence.
    """
    for fw in ("mcp", "langchain", "crewai", "autogen"):
        a = Agent(name="x", framework=fw, agent_evidence=[])
        out = gate([_f("x", "AG-NOAUTH")], [a])
        assert len(out) == 1, f"{fw} agent must not be gated"


def test_end_to_end_unproven_agent_yields_no_composition_findings():
    """Full detector run: a name-only 'agent' with dangerous caps stays quiet."""
    tool = Tool(name="execute_thing",
                capabilities=[ToolCapability.READ_DATA, ToolCapability.NETWORK_ACCESS])
    unproven = Agent(name="buildscript", framework="generic", agent_evidence=[],
                     tools=[tool])
    proven = Agent(name="realbot", framework="generic",
                   agent_evidence=["LLM client"], tools=[tool])
    quiet = run_all_detectors([unproven])
    loud = run_all_detectors([proven])
    assert all(f.witness for f in quiet), "unproven agent may only emit witness-backed findings"
    assert len(loud) >= len(quiet)


# --------------------------------------------------------------------------
# Agent evidence vs SERVER surface — two different questions.
# Regression for a bug I introduced: "HTTP server" was added as *agent* evidence to
# restore the CORS/NOAUTH recall fixtures, which made every Flask/FastAPI app an
# "agent". A third-party benchmark caught it on 13 of 22 pure web apps.
# --------------------------------------------------------------------------
def test_http_server_is_not_agent_evidence():
    from lucin.parsers.generic_parser import _collect_agent_evidence, has_server_surface
    flask = "from flask import Flask\napp = Flask(__name__)\n@app.route('/x')\ndef x(): ...\n"
    assert _collect_agent_evidence(flask, []) == [], "a web app is not an agent"
    assert has_server_surface(flask) is True, "...but it IS a server surface"


def test_server_surface_permits_findings_without_claiming_an_agent():
    """The finding gate must still judge an exposed server (AG-NOAUTH/AG-CORS),
    while the LABEL must not call it an agent."""
    a = Agent(name="app", framework="generic", agent_evidence=[], server_surface=True)
    assert a.is_evidence_backed is True, "server posture rules still apply"
    assert a.is_agent is False, "but it is not an agent"


def test_scan_result_only_claims_an_agent_when_evidenced():
    from lucin.models import ScanResult
    server_only = ScanResult(target="t", agents=[
        Agent(name="app", framework="generic", server_surface=True)])
    real = ScanResult(target="t", agents=[
        Agent(name="bot", framework="generic", agent_evidence=["@tool decorator"])])
    framework = ScanResult(target="t", agents=[Agent(name="c", framework="crewai")])
    assert server_only.has_evidence_backed_agent is False
    assert real.has_evidence_backed_agent is True
    assert framework.has_evidence_backed_agent is True, "framework parse = evidenced"
