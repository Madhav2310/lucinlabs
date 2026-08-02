"""Comprehensive real-world integration tests.

Tests Lucin against real code from popular open-source agent projects.
If any of these tests fail, it means a code change broke real-world detection.
"""

import pytest
from pathlib import Path
from lucin.scanner import scan_target

BASE = Path(__file__).parent.parent / "real_world_tests"


class TestRealWorldParsing:
    """Every real-world test case must parse correctly."""

    def test_01_langgraph_react(self):
        r = scan_target(BASE / "01_langchain_react/graph.py")
        assert len(r.agents) >= 1
        assert r.agents[0].framework == "langgraph"

    def test_02_langchain_python_repl(self):
        r = scan_target(BASE / "02_langchain_python_repl/agent.py")
        assert len(r.agents) == 1
        assert len(r.agents[0].tools) >= 2
        assert any(f.id == "AG-001" for f in r.findings)
        assert any(f.id == "AG-007" for f in r.findings)

    def test_03_openai_swarm_triage(self):
        r = scan_target(BASE / "03_openai_swarm_triage/agents.py")
        assert len(r.agents) == 3
        assert r.agents[0].framework == "swarm"

    def test_04_openai_swarm_airline(self):
        r = scan_target(BASE / "04_openai_swarm_airline/")
        assert len(r.agents) >= 5

    def test_05_mcp_filesystem(self):
        r = scan_target(BASE / "05_mcp_filesystem_config/claude_desktop_config.json")
        assert len(r.agents) == 1
        assert len(r.agents[0].mcp_servers) >= 7
        assert any(f.id == "AG-015" for f in r.findings)

    def test_06_crewai_trip_planner(self):
        r = scan_target(BASE / "06_crewai_trip_planner/trip_agents.py")
        assert len(r.agents) == 3
        total_tools = sum(len(a.tools) for a in r.agents)
        assert total_tools >= 7, f"Expected 7+ tools, got {total_tools}"
        assert len(r.findings) > 0, "CrewAI should have findings after cross-file fix"

    def test_07_openai_agents_sdk(self):
        r = scan_target(BASE / "07_openai_agents_sdk/web_search_agent.py")
        assert len(r.agents) == 1
        assert r.agents[0].framework == "openai_agents_sdk"

    def test_08_swe_agent_yaml(self):
        r = scan_target(BASE / "08_swe_agent/config.yaml")
        assert len(r.agents) >= 1
        assert any(f.id == "AG-001" for f in r.findings), "enable_bash_tool must trigger AG-001"

    def test_09_mcp_multi_server(self):
        r = scan_target(BASE / "09_mcp_multi_server/claude_desktop_config.json")
        assert len(r.agents[0].mcp_servers) >= 9
        assert any(f.id == "AG-007" for f in r.findings), "Secrets must be detected"
        assert any(f.id == "AG-015" for f in r.findings), "Supply chain must be detected"

    def test_10_composio_style(self):
        r = scan_target(BASE / "10_composio_style/agent.py")
        assert len(r.agents) == 1
        assert any(f.id == "AG-001" for f in r.findings)
        assert any(f.id == "AG-002" for f in r.findings)
        assert any(f.id == "AG-COMP" for f in r.findings)

    def test_11_autonomous_coder(self):
        r = scan_target(BASE / "11_dangerous_agent/autonomous_coder.py")
        assert len(r.findings) >= 8
        assert any(f.id == "AG-001" for f in r.findings)
        # CHANGED 2026-07-30 (fetch-vs-egress sink fix): this used to assert
        # AG-002. The fixture's only network tool is `browse` — a FETCH (data
        # in). AG-002 fired only because any unrecognised network tool defaulted
        # to "egress", the bug that produced fake trifecta sinks on 81 real repos
        # (`download_object`, `scrape_page`, `web_fetch_tool`). So the old AG-002
        # here was itself a false positive. Detection is NOT lost: the dangerous
        # agent still raises AG-TRIFECTA (witness-backed) + AG-001 x4 + AG-005a/b
        # + AG-006/010/028. We assert the sound, more precise signal instead.
        assert any(f.id == "AG-TRIFECTA" for f in r.findings)

    def test_12_autogen_team(self):
        r = scan_target(BASE / "12_autogen_code_exec/team.py")
        assert len(r.agents) >= 5
        assert any(f.id == "AG-001" for f in r.findings)
        assert any(f.id == "AG-026" for f in r.findings), "use_docker=False must fire AG-026"


class TestOWASPCoverage:
    """Verify OWASP ASI mapping works on real findings."""

    def test_findings_have_asi_mapping(self):
        r = scan_target(BASE / "11_dangerous_agent/autonomous_coder.py")
        for f in r.findings:
            assert len(f.owasp_asi) > 0, f"Finding {f.id} has no OWASP ASI mapping"

    def test_full_scan_covers_multiple_asi(self):
        r = scan_target(BASE / "09_mcp_multi_server/claude_desktop_config.json")
        all_asi = set()
        for f in r.findings:
            all_asi.update(f.owasp_asi)
        assert len(all_asi) >= 3, f"Expected 3+ ASI risks, got {all_asi}"


class TestScanMetadata:
    """Verify scan metadata is populated."""

    def test_metadata_populated(self):
        r = scan_target(BASE / "05_mcp_filesystem_config/claude_desktop_config.json")
        assert r.metadata.scanner_version == "0.2.0"
        assert "mcp" in r.metadata.frameworks_detected
        assert r.scan_duration_ms > 0

    def test_duration_reasonable(self):
        r = scan_target(BASE / "11_dangerous_agent/autonomous_coder.py")
        assert r.scan_duration_ms < 5000, f"Scan took {r.scan_duration_ms}ms — too slow!"
