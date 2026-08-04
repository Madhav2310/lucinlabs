from lucin.detectors import CROSS_AGENT_DETECTORS, PER_AGENT_DETECTORS, _detector_applies
from lucin.models import Agent


def test_detector_applicability():
    # Test that default detectors apply to normal agents
    generic_agent = Agent(name="test", framework="generic")
    mcp_agent = Agent(name="test", framework="mcp")
    skill_agent = Agent(name="test", framework="skill")

    # 1. Cross-origin only applies to MCP
    import lucin.detectors.cross_origin as cross_origin
    assert not _detector_applies(cross_origin.detect_cross_origin, generic_agent)
    assert _detector_applies(cross_origin.detect_cross_origin, mcp_agent)
    assert not _detector_applies(cross_origin.detect_cross_origin, skill_agent)

    # 2. Unauthenticated MCP only applies to MCP
    import lucin.detectors.mcp_auth as mcp_auth
    assert not _detector_applies(mcp_auth.detect_unauthenticated_mcp, generic_agent)
    assert _detector_applies(mcp_auth.detect_unauthenticated_mcp, mcp_agent)
    assert not _detector_applies(mcp_auth.detect_unauthenticated_mcp, skill_agent)

    # 3. SQL injection applies to all agent types, including skills (§3.1 of
    #    COVERAGE_AND_BUILD_PLAN.md classified it REUSE — it runs on bundled scripts).
    #    It was disabled on skills with no stated rationale in the original diff;
    #    PHASE_6_PLAN.md §2.8/§5.1.6 re-enables it.
    import lucin.detectors.sql_injection as sql_injection
    assert _detector_applies(sql_injection.detect_sql_injection, generic_agent)
    assert _detector_applies(sql_injection.detect_sql_injection, mcp_agent)
    assert _detector_applies(sql_injection.detect_sql_injection, skill_agent)

    # 4. A normal detector (like tool_poisoning) applies to all
    import lucin.detectors.tool_poisoning as tool_poisoning
    assert _detector_applies(tool_poisoning.detect_tool_poisoning, generic_agent)
    assert _detector_applies(tool_poisoning.detect_tool_poisoning, mcp_agent)
    assert _detector_applies(tool_poisoning.detect_tool_poisoning, skill_agent)
