"""Cross-agent lethal trifecta (Task 2, breadth): an untrusted source in agent A
reaching a dangerous sink in agent B via a delegation / handoff edge.

Reuses the shared AIFG type and query_trifecta over the merged multi-agent graph
(AgentGraph.to_aifg()), so this is one coherent model — agent-granular, per the
honest-scope docstring on AgentGraph.to_aifg.
"""

from lucin.aifg import TrifectaFinding
from lucin.multiagent.cascade import (
    AgentGraph, CascadeDetector, CrossAgentTrifecta, query_cross_agent_trifecta,
)


def _research_to_exfil_cluster() -> AgentGraph:
    """Realistic 3-agent scenario: a research agent ingesting UNTRUSTED web
    content hands off (via a coordinator) to a tool-holding agent that can exfil.
    This is the multi-agent EchoLeak / Morris-II handoff pattern."""
    g = AgentGraph()
    g.add_agent("researcher", role="web research", trust_level="untrusted",
                tools=["web_search", "scrape_website"], delegates_to=["coordinator"])
    g.add_agent("coordinator", role="router", trust_level="untrusted",
                tools=["summarize"], delegates_to=["operator"])
    g.add_agent("operator", role="ops", trust_level="untrusted",
                tools=["send_email", "http_post"], delegates_to=[])
    return g


class TestCrossAgentTrifecta:
    def test_fires_across_agent_boundary(self):
        findings = query_cross_agent_trifecta(_research_to_exfil_cluster())
        assert len(findings) == 1
        f = findings[0]
        assert isinstance(f, CrossAgentTrifecta)
        assert f.source_agent == "researcher"
        assert f.sink_agent == "operator"

    def test_handoff_path_is_the_delegation_chain(self):
        f = query_cross_agent_trifecta(_research_to_exfil_cluster())[0]
        assert f.handoff_path == ["researcher", "coordinator", "operator"]
        # the source and sink are genuinely different agents connected by handoff
        assert f.source_agent != f.sink_agent
        assert len(f.handoff_path) >= 2

    def test_names_the_dangerous_sink_tools(self):
        f = query_cross_agent_trifecta(_research_to_exfil_cluster())[0]
        assert set(f.dangerous_tools) == {"send_email", "http_post"}

    def test_underlying_finding_is_shared_aifg_type(self):
        """One coherent model: the finding is the SAME TrifectaFinding type SCAN
        emits, produced by the same query_trifecta run on the merged AIFG."""
        f = query_cross_agent_trifecta(_research_to_exfil_cluster())[0]
        assert isinstance(f.finding, TrifectaFinding)
        assert f.finding.egress_sink == "operator"

    def test_detector_convenience_method(self):
        det = CascadeDetector(_research_to_exfil_cluster())
        assert len(det.cross_agent_trifecta()) == 1

    def test_no_finding_without_dangerous_sink_agent(self):
        """No agent holds a dangerous tool → no egress sink → no trifecta."""
        g = AgentGraph()
        g.add_agent("a", trust_level="untrusted", tools=["web_search"],
                    delegates_to=["b"])
        g.add_agent("b", trust_level="untrusted", tools=["summarize"],
                    delegates_to=[])
        assert query_cross_agent_trifecta(g) == []

    def test_no_cross_agent_finding_for_single_self_contained_agent(self):
        """A lone high-privilege agent with no untrusted delegator is NOT a
        cross-agent finding (that is SCAN's single-file job, excluded here)."""
        g = AgentGraph()
        g.add_agent("solo", trust_level="untrusted",
                    tools=["send_email"], delegates_to=[])
        assert query_cross_agent_trifecta(g) == []

    def test_trusted_source_does_not_trigger(self):
        """If the only delegator is TRUSTED, there is no untrusted control origin
        → no cross-agent trifecta."""
        g = AgentGraph()
        g.add_agent("trusted_boss", trust_level="trusted", tools=["plan"],
                    delegates_to=["operator"])
        g.add_agent("operator", trust_level="trusted",
                    tools=["send_email"], delegates_to=[])
        assert query_cross_agent_trifecta(g) == []
