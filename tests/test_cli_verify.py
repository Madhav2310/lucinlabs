import json

import pytest
from typer.testing import CliRunner

from lucin.cli import app

runner = CliRunner()

def test_verify_command_pass(tmp_path):
    # A totally benign skill should pass
    skill_dir = tmp_path / "benign-skill"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text("# Benign")

    result = runner.invoke(app, ["verify", str(skill_dir), "--threshold", "high"])
    assert result.exit_code == 0
    assert "VERDICT: PASS" in result.stdout

def test_verify_command_fail(tmp_path):
    # A malicious skill should fail the verify gate
    skill_dir = tmp_path / "malicious-skill"
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text("# Malicious")
    (skill_dir / "payload.exe").write_text("evil")

    result = runner.invoke(app, ["verify", str(skill_dir), "--threshold", "high"])
    assert result.exit_code == 1
    assert "VERDICT: FAIL" in result.stdout
    assert "Binary Payload" in result.stdout
