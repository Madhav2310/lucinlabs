import tempfile
from pathlib import Path

import pytest

from lucin.detectors import _detector_applies
from lucin.detectors.skill_chain import detect_skill_chain
from lucin.detectors.skill_external import detect_external_instructions
from lucin.detectors.skill_manifest import detect_skill_manifest_gap
from lucin.detectors.sql_injection import detect_sql_injection
from lucin.models import SkillCapability
from lucin.parsers.skill_parser import parse_skill


def test_tencent_backdoor_reproduction():
    """The flagship fixture must be CRITICAL with a real witness — not INFO.

    PHASE_6_PLAN.md §2.2 found the previous version returned only an INFO
    finding on this exact fixture, so `lucin verify --threshold high` passed a
    live reconstructed backdoor. The redesigned detector proves a real
    source-to-sink flow (requests.get -> pickle.loads) instead of relying on
    manifest declaration for severity.
    """
    skill_dir = Path("tests/fixtures/skills/tencent_backdoor")
    agents = parse_skill(skill_dir)
    assert len(agents) == 1
    agent = agents[0]

    findings = detect_skill_chain(agent)
    assert len(findings) == 1
    f = findings[0]

    assert f.id == "AG-SKILL-CHAIN"
    assert f.severity.name == "CRITICAL"
    assert f.evidence_class.value == "witnessed"
    assert f.witness, "a CRITICAL flow finding must carry a witness a reader can open"
    assert "pickle.loads" in f.witness[0] or "deserialize" in f.witness[0]

    # Test external instructions detector
    findings_ext = detect_external_instructions(agent)
    assert len(findings_ext) == 0  # our poc doesn't fetch .md or .json, it fetches evil.com/payload

    # Test manifest gap detector
    findings_gap = detect_skill_manifest_gap(agent)
    assert len(findings_gap) == 1
    assert findings_gap[0].id == "AG-SKILL-MANIFEST-GAP"

def test_skill_manifest_gap():
    skill_dir = Path("tests/fixtures/skills/tencent_backdoor")
    agents = parse_skill(skill_dir)
    assert len(agents) == 1
    agent = agents[0]

    findings = detect_skill_manifest_gap(agent)
    assert len(findings) == 1
    assert findings[0].id == "AG-SKILL-MANIFEST-GAP"
    assert "remote_fetch" in findings[0].description # Deterministic taxonomy removes fuzzy compatibility matching, so remote_fetch is UNDECLARED!
    assert "exec" in findings[0].description
    assert "decode" in findings[0].description
    assert "deserialize" in findings[0].description


def test_sql_injection_fires_on_a_bundled_skill_script():
    """§2.8/§5.1.6: SQL injection was disabled on skills (`applies_to = {"all", "-skill"}`)
    with no stated rationale, even though §3.1 of the build plan classified it REUSE — it
    is supposed to run on bundled scripts via `Tool.source_file`, same as on any other
    artifact. This is a positive-fixture check, not just a flag flip: it proves the
    detector actually fires on a skill script, not merely that `applies_to` allows it.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        skill_dir = Path(tmpdir) / "db-helper"
        skill_dir.mkdir()
        (skill_dir / "SKILL.md").write_text(
            "---\nname: db-helper\ndescription: test\n---\nQueries a database.\n"
        )
        scripts_dir = skill_dir / "scripts"
        scripts_dir.mkdir()
        (scripts_dir / "query.py").write_text(
            "import sqlite3\n"
            "def query_db(user_input: str, conn):\n"
            "    cur = conn.cursor()\n"
            "    cur.execute(f\"SELECT * FROM users WHERE name = '{user_input}'\")\n"
            "    return cur.fetchall()\n"
        )

        agents = parse_skill(skill_dir)
        agent = agents[0]

        assert _detector_applies(detect_sql_injection, agent)
        findings = detect_sql_injection(agent)
        assert len(findings) == 1
        assert findings[0].id == "AG-SQL"
