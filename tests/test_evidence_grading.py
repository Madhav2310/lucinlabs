"""AG-001 severity is graded by EVIDENCE, not by the tool's name.

Measured driver (81 real agent repos, 2026-07-30): unioning name-inferred
capabilities with body evidence made AG-001 the largest false-positive source
(92 of 429 HIGH/CRIT findings) — firing CRITICAL on `printable_shell_command`
(body: `oslex.join`, i.e. shell ESCAPING), `_format_shell_call` (a console
formatter) and even a static analyzer that merely *looks for* `shell=True`.

Deleting those findings outright cost 4 REAL recall cases (class-based toolkits
hide exec behind `self._docker_exec(...)`), so instead we keep reporting them and
grade the severity:
    body-confirmed exec  -> CRITICAL
    name-only inference  -> MEDIUM  (+ a witness that says so)
"""
import ast
import textwrap

from lucin.detectors.shell_access import detect_unrestricted_shell
from lucin.models import Agent, Severity, Tool, ToolCapability
from lucin.parsers.body_inspector import exec_is_body_confirmed


def _tool(name: str, confirmed: bool | None) -> Tool:
    return Tool(name=name, capabilities=[ToolCapability.EXECUTE_CODE],
                exec_body_confirmed=confirmed)


def _finding(tool: Tool):
    out = detect_unrestricted_shell(Agent(name="a", tools=[tool]))
    assert len(out) == 1, "AG-001 must still FIRE regardless of grade (recall)"
    return out[0]


def test_body_confirmed_exec_is_critical():
    f = _finding(_tool("run_shell", confirmed=True))
    assert f.severity == Severity.CRITICAL
    assert "confirmed by body inspection" in f.witness[0]


def test_name_only_inference_is_medium_not_critical():
    f = _finding(_tool("printable_shell_command", confirmed=False))
    assert f.severity == Severity.MEDIUM, "name-only exec must not claim CRITICAL"
    assert "name-inferred" in f.title.lower()
    # The witness must be TRUTHFUL about how we concluded it.
    assert "inferred from its NAME" in f.witness[0]
    assert "found NO exec sink" in f.witness[0]


def test_unknown_evidence_keeps_legacy_critical():
    """No body available (MCP/remote/description-only) -> unchanged behaviour.

    Absence of a body is not evidence of safety, so we must NOT downgrade.
    """
    f = _finding(_tool("execute_command", confirmed=None))
    assert f.severity == Severity.CRITICAL


def _fn(src: str):
    tree = ast.parse(textwrap.dedent(src))
    fn = [n for n in ast.walk(tree)
          if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))][0]
    return fn, tree


def test_exec_confirmation_follows_self_method_callees():
    """Class-based toolkits: exec behind `self._helper()` must be CONFIRMED.

    Regression for the 4 real recall misses (camel terminal/docker/code-exec,
    promptflow REPL): callee resolution keyed on the dotted name
    ("self._docker_exec"), which never matched the bare-name function map.
    """
    fn, tree = _fn('''
        class Toolkit:
            def run_command(self, cmd: str):
                """Run a shell command."""
                return self._do_exec(cmd)

            def _do_exec(self, cmd):
                import subprocess
                return subprocess.run(cmd, shell=True)
    ''')
    assert exec_is_body_confirmed(fn, tree) is True


def test_shell_escaping_helper_is_not_confirmed_exec():
    """`printable_shell_command` FORMATS a command; it does not run one."""
    fn, tree = _fn('''
        def printable_shell_command(cmd_list):
            """Convert a list of command arguments to a shell-escaped string."""
            return oslex.join(cmd_list)
    ''')
    assert exec_is_body_confirmed(fn, tree) is False


def test_real_exec_is_confirmed():
    fn, tree = _fn('''
        def run_cmd(cmd):
            import subprocess
            return subprocess.run(cmd, shell=True)
    ''')
    assert exec_is_body_confirmed(fn, tree) is True
