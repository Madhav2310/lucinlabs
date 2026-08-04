"""Regression tests for skill_parser.py's path-escape and resource-limit hardening.

Phase 6 §5.1.2 / §2.5: the parser previously read any file a symlink or
`../` pointed at, with no root check and no size cap — a security scanner
reading attacker-designated paths off the host. These tests pin the fix.
"""
import os
from pathlib import Path

import pytest

from lucin.parsers.skill_parser import MAX_FILE_BYTES, parse_skill


def _make_skill(tmp_path: Path, name: str = "my-skill") -> Path:
    skill_dir = tmp_path / name
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text(
        "---\nname: " + name + "\ndescription: test\n---\nBody.\n"
    )
    return skill_dir


def test_symlinked_reference_outside_root_is_not_read(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "private.md").write_text("SECRET_KEY=hunter2")

    skill_dir = _make_skill(tmp_path)
    ref_dir = skill_dir / "references"
    ref_dir.mkdir()
    (ref_dir / "leak.md").symlink_to(outside / "private.md")

    agents = parse_skill(skill_dir)
    assert len(agents) == 1
    skill = agents[0].skill

    # The secret must never appear in any parsed instruction text.
    assert not any("hunter2" in b.text for b in skill.instructions)
    assert any("escapes skill root" in d for d in skill.diagnostics)


def test_symlinked_scripts_dir_outside_root_is_not_walked(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "evil.py").write_text("import subprocess; subprocess.run(['id'])")

    skill_dir = _make_skill(tmp_path)
    (skill_dir / "scripts").symlink_to(outside)

    agents = parse_skill(skill_dir)
    skill = agents[0].skill

    assert skill.scripts == []
    assert any("escapes skill root" in d for d in skill.diagnostics)


def test_dotdot_reference_outside_root_is_not_read(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "private.md").write_text("SECRET_KEY=hunter2")

    skill_dir = _make_skill(tmp_path)
    ref_dir = skill_dir / "references"
    ref_dir.mkdir()
    # A relative `../` escape rather than a symlink — same root-escape class.
    (ref_dir / "leak.md").symlink_to(Path("..") / ".." / "outside" / "private.md")

    agents = parse_skill(skill_dir)
    skill = agents[0].skill
    assert not any("hunter2" in b.text for b in skill.instructions)


def test_symlink_cycle_does_not_crash(tmp_path):
    skill_dir = _make_skill(tmp_path)
    scripts_dir = skill_dir / "scripts"
    scripts_dir.mkdir()
    cycle = scripts_dir / "loop"
    cycle.symlink_to(cycle)  # self-referential symlink

    # Must complete without raising, regardless of what it finds.
    agents = parse_skill(skill_dir)
    assert len(agents) == 1


def test_oversized_file_is_skipped_not_read(tmp_path):
    skill_dir = _make_skill(tmp_path)
    scripts_dir = skill_dir / "scripts"
    scripts_dir.mkdir()
    big = scripts_dir / "huge.py"
    big.write_bytes(b"# " + b"x" * (MAX_FILE_BYTES + 1024))

    agents = parse_skill(skill_dir)
    skill = agents[0].skill

    assert skill.scripts == []
    assert any("exceeds" in d for d in skill.diagnostics)


def test_non_utf8_bytes_do_not_crash(tmp_path):
    skill_dir = _make_skill(tmp_path)
    (skill_dir / "SKILL.md").write_bytes(
        b"---\nname: my-skill\ndescription: test\n---\n\xff\xfe\x00 not utf8 \xc3\x28\n"
    )

    agents = parse_skill(skill_dir)
    assert len(agents) == 1  # completes cleanly, no traceback
