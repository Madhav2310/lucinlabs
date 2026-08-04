"""`lucin scan --ci --fail-on` exit-code contract.

WHY THIS TEST EXISTS
--------------------
Two production bugs lived on this path at once, both found 2026-08-04:

1. **An unanalysable target exited 0.** `lucin scan ./rust-agent --ci --fail-on high`
   passed CI on an agent that shelled out to attacker-controlled input, because
   zero files were parsed and therefore zero findings were produced. Silence from
   a target we could not read is absence of evidence, not evidence of absence.

2. **Any INFO finding crashed the command.** `severity_order` in `scan` omitted
   `"info"`, so `severity_order.index(finding.severity.value)` raised
   `ValueError: 'info' is not in list` and the command died with a traceback
   instead of gating. `verify` already had the complete list; `scan` did not.

THE CONTRACT
    exit 0  scanned successfully, nothing at or above the threshold
    exit 1  scanned successfully, findings at or above the threshold
    exit 2  could not analyse the target, or the --fail-on value is invalid

Exit 2 is deliberately distinct from 1 so a pipeline can tell "unable to analyse"
apart from "analysed and failed" — they demand different responses.
"""
from typer.testing import CliRunner

from lucin.cli import app

runner = CliRunner()

RUST_AGENT = """\
use std::process::Command;
fn run_tool(user_cmd: &str) -> String {
    Command::new("sh").arg("-c").arg(user_cmd).output().unwrap();
    String::new()
}
"""

VULNERABLE_PY = """\
from langchain.tools import tool
import subprocess

@tool
def run(cmd: str) -> str:
    \"\"\"Run a command.\"\"\"
    return subprocess.check_output(cmd, shell=True).decode()
"""

CLEAN_PY = """\
from langchain.tools import tool

@tool
def add(a: int, b: int) -> int:
    \"\"\"Add two numbers.\"\"\"
    return a + b
"""


def test_unanalysable_target_never_passes_ci(tmp_path):
    """A language we cannot read must not be reported to CI as passing."""
    (tmp_path / "main.rs").write_text(RUST_AGENT)
    result = runner.invoke(app, ["scan", str(tmp_path), "--ci", "--fail-on", "high"])
    assert result.exit_code == 2, (
        f"expected exit 2 (unable to analyse), got {result.exit_code}. "
        "A Rust agent with a live command injection must not pass CI."
    )


def test_findings_at_threshold_exit_1(tmp_path):
    """The ordinary gating path still works."""
    (tmp_path / "agent.py").write_text(VULNERABLE_PY)
    result = runner.invoke(app, ["scan", str(tmp_path), "--ci", "--fail-on", "high"])
    assert result.exit_code == 1, f"expected exit 1, got {result.exit_code}"


def test_info_findings_do_not_crash_the_gate(tmp_path):
    """An INFO finding must gate, not raise ValueError.

    Regression for `ValueError: 'info' is not in list` — the crash meant any scan
    producing an INFO finding died with a traceback under --ci.
    """
    (tmp_path / "agent.py").write_text(CLEAN_PY)
    result = runner.invoke(app, ["scan", str(tmp_path), "--ci", "--fail-on", "high"])
    assert result.exit_code in (0, 1), (
        f"exit {result.exit_code}; --fail-on crashed instead of gating: "
        f"{result.exception!r}"
    )
    assert not isinstance(result.exception, ValueError), result.exception


def test_invalid_fail_on_value_is_rejected(tmp_path):
    """A typo in --fail-on must fail loudly, not silently gate on nothing."""
    (tmp_path / "agent.py").write_text(VULNERABLE_PY)
    result = runner.invoke(app, ["scan", str(tmp_path), "--ci", "--fail-on", "bogus"])
    assert result.exit_code == 2, f"expected exit 2 for a bad threshold, got {result.exit_code}"
