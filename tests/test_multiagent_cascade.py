"""Tests for cascading failure detection across multi-agent graphs."""

from lucin.multiagent.cascade import AgentGraph, CascadeDetector


def test_cascade_no_dangerous_tools():
    graph = AgentGraph()
    graph.add_agent("triage", delegates_to=["sales", "refunds"])
    graph.add_agent("sales")
    graph.add_agent("refunds")

    detector = CascadeDetector(graph)
    report = detector.propagate_failure("triage")

    assert report.r_zero == 0.0
    assert report.blast_radius == {"sales", "refunds"}
    assert len(report.highest_risk_paths) > 0 # Returns default paths even if no high risk

def test_cascade_with_dangerous_tools():
    graph = AgentGraph()
    graph.add_agent("triage", delegates_to=["sales", "refunds"])
    graph.add_agent("sales", tools=["send_email"], delegates_to=["email_processor"])
    graph.add_agent("refunds", tools=["payment_processor"], delegates_to=["accounting"])
    graph.add_agent("email_processor")
    graph.add_agent("accounting")

    detector = CascadeDetector(graph)
    report = detector.propagate_failure("triage")

    assert report.r_zero > 0.0
    assert report.blast_radius == {"sales", "refunds", "email_processor", "accounting"}
    assert "triage" not in report.blast_radius

    paths = [" -> ".join(p) for p in report.highest_risk_paths]
    assert any("triage -> sales -> email_processor" in p for p in paths) or any("triage -> refunds -> accounting" in p for p in paths)
