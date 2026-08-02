"""C1 regression: the scanner must exclude vendored/build/VCS directories.

Root cause this guards against: `_detect_binary_payloads` used to rglob the WHOLE
tree — including `venv/`, `node_modules/`, `.git/`, `site-packages/` — and flag every
`.so`/`.dll`/`.dylib`/`.sh` as a HIGH "binary payload". Running `lucin scan .` on
any real project with a virtualenv therefore emitted a wall of false HIGHs, refuting the
published "0 false positives" precision claim in the field.

These tests assert:
  1. A fake `venv/` full of binaries + scripts yields ZERO findings from those files.
  2. A real agent file sitting next to that `venv/` still produces its real finding —
     and ONLY that finding (no venv HIGHs leak in).
  3. Shell scripts (.sh) are not treated as binary payloads anywhere.
  4. The binary-payload check does not run at all when no agents are parsed.
"""

import tempfile
from pathlib import Path

import pytest

from lucin.scanner import scan_target
from lucin._fs import EXCLUDED_DIR_NAMES, iter_files, is_excluded


@pytest.fixture
def tmp_dir():
    with tempfile.TemporaryDirectory() as d:
        yield Path(d)


def _make_vendored_binaries(root: Path, subdir: str) -> None:
    """Drop binary + script files inside a vendored subdirectory."""
    vend = root / subdir / "some_pkg"
    vend.mkdir(parents=True)
    (vend / "_native.so").write_bytes(b"\x7fELF fake shared object")
    (vend / "engine.dll").write_bytes(b"MZ fake dll")
    (vend / "lib.dylib").write_bytes(b"\xca\xfe\xba\xbe fake dylib")
    (vend / "install.sh").write_text("#!/bin/sh\necho hello\n")
    (vend / "blob.bin").write_bytes(b"\x00\x01\x02\x03")


def test_venv_binaries_produce_no_findings(tmp_dir):
    """A tree whose ONLY content is a vendored venv with binaries → 0 findings."""
    _make_vendored_binaries(tmp_dir, "venv")
    result = scan_target(tmp_dir)
    assert result.findings == [], (
        f"venv binaries must not produce findings; got: "
        f"{[(f.id, f.source_file) for f in result.findings]}"
    )


def test_real_agent_beside_venv_yields_only_real_finding(tmp_dir):
    """A real vulnerable agent next to a venv → the agent's finding, no venv HIGHs."""
    _make_vendored_binaries(tmp_dir, "venv")
    (tmp_dir / "agent.py").write_text(
        '''
from langchain.tools import tool
import subprocess

@tool
def execute_shell(command: str) -> str:
    """Execute a shell command."""
    return subprocess.run(command, shell=True, capture_output=True).stdout
'''
    )
    result = scan_target(tmp_dir)

    # No finding may point at anything inside the vendored dir.
    venv_findings = [f for f in result.findings if f.source_file and "venv" in f.source_file]
    assert venv_findings == [], (
        f"no finding may come from venv/; got: "
        f"{[(f.id, f.source_file) for f in venv_findings]}"
    )
    # No binary-payload (AG-015 HIGH from _detect_binary_payloads) finding at all.
    binary_payloads = [f for f in result.findings if "Binary Payload" in f.title]
    assert binary_payloads == [], "binary-payload detector fired on excluded dirs"
    # The real agent IS still detected.
    assert any(f.id == "AG-001" for f in result.findings), "real agent finding was lost"


@pytest.mark.parametrize("vendor", ["node_modules", ".git", "site-packages", "build", "dist"])
def test_other_vendored_dirs_excluded(tmp_dir, vendor):
    _make_vendored_binaries(tmp_dir, vendor)
    result = scan_target(tmp_dir)
    assert result.findings == [], f"{vendor}/ binaries must not produce findings"


def test_dist_info_dirs_excluded(tmp_dir):
    """`*.dist-info` package-metadata dirs are excluded by suffix."""
    _make_vendored_binaries(tmp_dir, "somepkg-1.2.3.dist-info")
    result = scan_target(tmp_dir)
    assert result.findings == []


def test_shell_scripts_are_not_binary_payloads(tmp_dir):
    """Even in a scanned skill dir with a real agent, a .sh file is not a payload."""
    (tmp_dir / "agent.py").write_text(
        '''
from langchain.tools import tool

@tool
def read_db(query: str) -> str:
    """Query the customer database."""
    pass
'''
    )
    (tmp_dir / "setup.sh").write_text("#!/bin/sh\necho setup\n")
    result = scan_target(tmp_dir)
    payloads = [f for f in result.findings if "Binary Payload" in f.title]
    assert payloads == [], ".sh must not be flagged as a binary payload"


def test_binary_check_skipped_when_no_agents(tmp_dir):
    """With zero parseable agents, a real binary in the tree is NOT flagged.

    The binary-payload check only applies to genuine skill/agent directories.
    """
    (tmp_dir / "payload.so").write_bytes(b"\x7fELF fake")
    (tmp_dir / "notes.txt").write_text("just some text, no agent here")
    result = scan_target(tmp_dir)
    assert result.findings == [], (
        "binary-payload check must not run when no agents are found"
    )


def test_binary_payload_still_detected_in_real_skill_dir(tmp_dir):
    """Precision guard: a genuine binary in a real skill dir IS still flagged.

    Ensures the exclusion + agent-gating did not neuter the detector entirely.
    """
    (tmp_dir / "agent.py").write_text(
        '''
from langchain.tools import tool

@tool
def helper(x: str) -> str:
    """A helper tool."""
    pass
'''
    )
    (tmp_dir / "payload.so").write_bytes(b"\x7fELF fake shared object")
    result = scan_target(tmp_dir)
    payloads = [f for f in result.findings if "Binary Payload" in f.title]
    assert len(payloads) == 1, "a binary in a real skill dir should still be flagged"
    assert payloads[0].source_file.endswith("payload.so")


# --- unit tests for the shared exclusion helper --------------------------------

def test_is_excluded_helper():
    root = Path("/proj")
    assert is_excluded(Path("/proj/venv/lib/x.so"), root)
    assert is_excluded(Path("/proj/node_modules/pkg/index.js"), root)
    assert is_excluded(Path("/proj/pkg-1.0.dist-info/RECORD"), root)
    assert not is_excluded(Path("/proj/src/agent.py"), root)


def test_iter_files_prunes_vendored(tmp_dir):
    (tmp_dir / "src").mkdir()
    (tmp_dir / "src" / "agent.py").write_text("x = 1")
    (tmp_dir / "venv").mkdir()
    (tmp_dir / "venv" / "dep.py").write_text("y = 2")
    found = iter_files(tmp_dir, "*.py")
    names = {p.name for p in found}
    assert "agent.py" in names
    assert "dep.py" not in names


def test_excluded_dir_names_cover_common_vendors():
    for expected in ("venv", ".venv", "node_modules", ".git", "site-packages",
                     "dist", "build", "__pycache__"):
        assert expected in EXCLUDED_DIR_NAMES
