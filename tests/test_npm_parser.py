from pathlib import Path

import pytest

from lucin.models import SkillCapability
from lucin.parsers import detect_and_parse


def test_npm_package_json_parsing(tmp_path):
    """
    Test that package.json dependencies are parsed and mapped to capabilities.
    """
    skill_dir = tmp_path / "node-skill"
    skill_dir.mkdir()

    (skill_dir / "SKILL.md").write_text("# Node Skill\n")

    (skill_dir / "package.json").write_text(
        '{\n'
        '  "dependencies": {\n'
        '    "axios": "^1.6.0",\n'
        '    "fs-extra": "11.1.0"\n'
        '  }\n'
        '}\n'
    )

    agents = detect_and_parse(skill_dir)
    assert len(agents) == 1
    agent = agents[0]

    assert "axios" in agent.skill.dependencies
    assert "fs-extra" in agent.skill.dependencies

    # Regression pin (PHASE_6_PLAN.md §2.3/§5.2.3): listing a dependency in
    # package.json/requirements.txt must NOT count as declaring the capability
    # it implies — that was a real bug (honestly declaring your dependencies
    # used to suppress findings instead of informing them). Dependency parsing
    # still happens (asserted above); it just no longer feeds `reconcile`.
    from lucin.detectors.skill_declaration import reconcile
    report = reconcile(agent.skill.observed_capabilities, agent.skill.declared_capabilities, "")
    assert SkillCapability.REMOTE_FETCH not in report.declared_via_allowed_tools
    assert SkillCapability.REMOTE_FETCH not in report.declared_via_compatibility
