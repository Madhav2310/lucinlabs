"""Tests for the interactive HTML report (Track B — AIFG graph upgrade).

Covers: trifecta graph rendering + witness chain, empty-findings graph,
XSS escaping, graceful degrade on AIFG-build failure, and the self-contained
(no-CDN) invariant.
"""

import json
import re

import pytest

from lucin.models import Agent, Finding, ScanResult, Severity, Tool, ToolCapability
from lucin import html_report
from lucin.html_report import generate_html_report


def _trifecta_agent() -> Agent:
    """An agent whose AIFG yields a real lethal-trifecta path:
    retrieve_docs (untrusted input + secret) -> __llm__ -> send_email (egress).
    """
    return Agent(
        name="trifecta_agent",
        tools=[
            Tool(name="retrieve_docs",
                 capabilities=[ToolCapability.READ_DATA, ToolCapability.NETWORK_ACCESS],
                 source_file="agent.py", source_line=3),
            Tool(name="read_db",
                 capabilities=[ToolCapability.READ_DATA],
                 source_file="agent.py", source_line=8),
            Tool(name="send_email",
                 capabilities=[ToolCapability.NETWORK_ACCESS],
                 source_file="agent.py", source_line=12),
        ],
        source_file="agent.py",
    )


def _trifecta_finding() -> Finding:
    return Finding(
        id="AG-TRIFECTA",
        title="Information-Flow Exfiltration Path -> 'send_email'",
        severity=Severity.CRITICAL,
        description="Lethal trifecta detected.",
        agent_name="trifecta_agent",
        owasp_ref="A01 - Agent Goal Hijack",
        fix_suggestion="Restrict send_email.",
        witness=[
            "control: retrieve_docs → __llm__ → send_email",
            "data:    read_db → __llm__ → send_email",
        ],
    )


def _extract_aifg_json(html_str: str) -> dict:
    m = re.search(r'id="aifg-data"[^>]*>(.*?)</script>', html_str, re.S)
    assert m, "aifg-data script island not found"
    return json.loads(m.group(1))


# --- (a) trifecta present ---------------------------------------------------

def test_trifecta_finding_renders_graph_witness_and_red_marks():
    result = ScanResult(
        target="agent.py",
        agents=[_trifecta_agent()],
        findings=[_trifecta_finding()],
    )
    out = generate_html_report(result)

    # graph data island present
    assert '<script id="aifg-data"' in out

    # a red-marked (trifecta) node AND edge exist in the embedded graph data
    data = _extract_aifg_json(out)
    assert any(n["trifecta"] for n in data["nodes"]), "no trifecta-marked node"
    assert any(e["trifecta"] for e in data["edges"]), "no trifecta-marked edge"
    red_names = {n["name"] for n in data["nodes"] if n["trifecta"]}
    assert {"retrieve_docs", "send_email"} <= red_names

    # witness chain text rendered in the finding card
    assert "Proof-witness path" in out
    assert "retrieve_docs" in out
    assert "send_email" in out

    # min-cut remediation rendered for the trifecta finding
    assert "Min-cut fix" in out

    # MITRE ATLAS tag alongside OWASP
    assert "MITRE ATLAS" in out
    assert "AML.T0" in out


# --- (b) zero findings ------------------------------------------------------

def test_zero_findings_renders_graph_without_cards():
    result = ScanResult(
        target="benign.py",
        agents=[
            Agent(name="benign", tools=[
                Tool(name="knowledge_search", capabilities=[ToolCapability.READ_DATA]),
                Tool(name="log_write", capabilities=[ToolCapability.WRITE_DATA]),
            ]),
        ],
        findings=[],
    )
    out = generate_html_report(result)  # must not raise

    # graph section present
    assert '<script id="aifg-data"' in out
    assert "Agent Information-Flow Graph" in out

    # no finding-card section
    assert 'class="finding ' not in out
    assert '<h2 class="section-title">Findings</h2>' not in out


# --- (c) XSS escaping -------------------------------------------------------

def test_xss_payload_is_escaped():
    payload = '<script>alert(1)</script>'
    result = ScanResult(
        target="x.py",
        agents=[Agent(name="a", tools=[Tool(name="t", capabilities=[ToolCapability.READ_DATA])])],
        findings=[
            Finding(
                id="AG-001",
                title=payload + ' "quote"',
                severity=Severity.HIGH,
                description=payload + ' with a " double quote',
                agent_name="a",
            ),
        ],
    )
    out = generate_html_report(result)

    # escaped form present
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in out
    # the live payload must NOT appear as markup
    assert "<script>alert(1)" not in out


# --- (d) graceful degrade on AIFG-build failure -----------------------------

def test_aifg_build_failure_degrades_to_findings_only(monkeypatch):
    def boom(agent):
        raise RuntimeError("adapter exploded")

    # patch the adapter used inside _build_graph_section's local import
    import lucin.aifg as aifg
    monkeypatch.setattr(aifg, "build_aifg", boom)

    result = ScanResult(
        target="x.py",
        agents=[_trifecta_agent()],
        findings=[_trifecta_finding()],
    )
    out = generate_html_report(result)  # must not raise

    # graph island absent (degraded), but findings still render
    assert '<script id="aifg-data"' not in out
    assert 'class="finding ' in out
    assert "Lucin Security Report" in out


def test_no_agents_degrades_without_graph():
    result = ScanResult(target="x.py", agents=[], findings=[])
    out = generate_html_report(result)  # must not raise
    assert '<script id="aifg-data"' not in out
    assert "Lucin Security Report" in out


# --- self-contained (no CDN) ------------------------------------------------

def test_no_cdn_resource_references():
    result = ScanResult(
        target="agent.py",
        agents=[_trifecta_agent()],
        findings=[_trifecta_finding()],
    )
    out = generate_html_report(result)

    # no external stylesheet/script/img resource load over http(s)
    cdn = re.findall(r'(?:src|href)\s*=\s*"(https?://[^"]+)"', out)
    non_footer = [u for u in cdn if "github.com/Madhav2310/lucinlabs" not in u]
    assert non_footer == [], f"found CDN resource refs: {non_footer}"
