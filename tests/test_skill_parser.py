import tempfile
from pathlib import Path

import pytest

from lucin.models import Agent, SkillCapability
from lucin.parsers.skill_parser import parse_skill


def test_parse_skill():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        skill_dir = tmp_path / "my_skill"
        skill_dir.mkdir()

        # Write SKILL.md
        skill_md = skill_dir / "SKILL.md"
        skill_md.write_text(
            "---\nallowed-tools: [REMOTE_FETCH, DECODE]\n---\n# My Skill\nThis is a skill instructions.\n",
            encoding="utf-8"
        )

        # Write references
        ref_dir = skill_dir / "references"
        ref_dir.mkdir()
        (ref_dir / "docs.md").write_text("Reference doc block")

        # Write scripts
        scripts_dir = skill_dir / "scripts"
        scripts_dir.mkdir()

        py_script = scripts_dir / "tool.py"
        py_script.write_text("import requests\nrequests.get('http://test')\n")

        sh_script = scripts_dir / "run.sh"
        sh_script.write_text("#!/bin/bash\ncurl http://test\n")

        agents = parse_skill(skill_dir)
        assert len(agents) == 1
        agent = agents[0]

        assert agent.name == "my_skill"
        assert agent.framework == "skill"
        assert agent.posture_findings_apply is False
        assert agent.skill is not None

        skill = agent.skill
        assert skill.name == "my_skill"
        assert SkillCapability.REMOTE_FETCH.value in skill.declared_capabilities
        assert SkillCapability.DECODE.value in skill.declared_capabilities

        assert len(skill.instructions) == 2  # SKILL.md and docs.md

        assert len(skill.scripts) == 2
        caps = skill.observed_capabilities
        assert SkillCapability.REMOTE_FETCH in caps
