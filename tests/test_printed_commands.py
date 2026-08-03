"""Any command Lucin tells a user to run must actually run."""
import shlex
import subprocess

import pytest


def _scan_output():
    return subprocess.run(
        ["lucin", "scan", "examples/vulnerable-agent/", "--no-telemetry"],
        capture_output=True, text=True,
    ).stdout


def test_fix_hints_are_valid_invocations():
    hints = sorted({
        l.split("→", 1)[1].strip().rstrip("│").strip()
        for l in _scan_output().splitlines() if "→ lucin" in l
    })
    assert hints, "no fix hints found in scan output"
    for h in hints:
        r = subprocess.run(shlex.split(h), capture_output=True, text=True)
        combined = r.stdout + r.stderr
        assert "No such option" not in combined, f"broken hint: {h}"
        assert "Usage:" not in combined.split("\n")[0], f"hint failed to parse: {h}"


@pytest.mark.parametrize("cmd", [
    "lucin scan --list-rules",
    "lucin scan --list-adapters",
    "lucin scan examples/vulnerable-agent/ --no-telemetry",
    "lucin info examples/vulnerable-agent/",
    "lucin badge examples/vulnerable-agent/ --style score",
    "lucin explain AG-001",
])
def test_documented_commands_run(cmd):
    r = subprocess.run(shlex.split(cmd), capture_output=True, text=True)
    assert "No such option" not in r.stdout + r.stderr, cmd
