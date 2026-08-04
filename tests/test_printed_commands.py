"""Any command Lucin tells a user to run must actually run."""
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

# Documented invocations. Each must exit 0 and print no traceback: this file is
# the guard behind the README's claim that every printed command is real.
DOCUMENTED = [
    "lucin scan --list-rules",
    "lucin scan --list-adapters",
    "lucin scan examples/vulnerable-agent/ --no-telemetry",
    "lucin info examples/vulnerable-agent/",
    "lucin badge examples/vulnerable-agent/ --style score",
    "lucin explain AG-001",
]


def _lucin_argv() -> list[str]:
    """Resolve the `lucin` entry point without relying on PATH.

    pytest does not run with the venv's bin/ on PATH unless the venv was
    activated, so shelling out to a bare "lucin" raises FileNotFoundError even
    though the console script is installed. Every test in this file failed that
    way, which meant the suite guarding "documented commands really run" was
    itself not running. Prefer the console script next to the interpreter
    executing the tests, and fall back to `python -m lucin`.
    """
    bindir = Path(sys.executable).parent
    for name in ("lucin", "lucin.exe"):
        script = bindir / name
        if script.exists():
            return [str(script)]
    return [sys.executable, "-m", "lucin"]


def _run(cmd: str) -> subprocess.CompletedProcess:
    argv = shlex.split(cmd)
    assert argv and argv[0] == "lucin", f"not a lucin invocation: {cmd}"
    return subprocess.run(_lucin_argv() + argv[1:], capture_output=True, text=True)


def _assert_ran(result: subprocess.CompletedProcess, cmd: str) -> None:
    combined = result.stdout + result.stderr
    assert "No such option" not in combined, f"unknown option: {cmd}"
    assert "Usage:" not in combined.split("\n")[0], f"failed to parse: {cmd}"
    assert "Traceback (most recent call last)" not in combined, (
        f"crashed: {cmd}\n{result.stderr[-800:]}"
    )
    # Checking only the text left a command that exits non-zero passing, which
    # is most of what "actually run" means to a reader following the docs.
    assert result.returncode == 0, (
        f"exit {result.returncode}: {cmd}\n{combined[-800:]}"
    )


@pytest.mark.parametrize("cmd", DOCUMENTED)
def test_documented_commands_run(cmd):
    _assert_ran(_run(cmd), cmd)


def test_fix_hints_are_valid_invocations():
    """Every `→ lucin ...` hint printed in a scan has to be runnable as printed."""
    scan = _run("lucin scan examples/vulnerable-agent/ --no-telemetry")
    hints = sorted({
        line.split("→", 1)[1].strip().rstrip("│").strip()
        for line in scan.stdout.splitlines() if "→ lucin" in line
    })
    assert hints, "no fix hints found in scan output"
    for hint in hints:
        _assert_ran(_run(hint), hint)
