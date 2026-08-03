"""Kind-scoped sanitizer/barrier model (the AG-001 guard check).

Measured 2026-07-30: with no sanitizer model, AG-001 reported CRITICAL
"Unrestricted Shell/Exec Access" on all of these —

    subprocess.run(cmd, shell=True)                       # genuinely dangerous
    subprocess.run(f"ls {shlex.quote(cmd)}", shell=True)   # SANITIZED (our own fix)
    subprocess.run(shlex.split(cmd), shell=False)          # safe argv form
    subprocess.run(["git", "status"], shell=False)         # no user input at all

— i.e. we flagged code for not applying `shlex.quote`, then flagged it again once it
had. Artemis (arXiv:2502.21026) measured that weak sanitizer/propagation rules cause
**9.2x more false positives**, the largest single effect in the SOTA survey.

Sanitizers are KIND-SCOPED (Pysa's `Sanitize[TaintSink[SQL]]` model): `shlex.quote`
neutralises COMMAND sinks and must NOT silence SQL/PATH sinks.
"""
import ast
import textwrap

import pytest

from lucin.analysis.sanitizers import (
    SinkKind,
    call_is_shell_free_argv,
    command_is_fully_literal,
    exec_guard_status,
    is_argv_builder,
    sanitizer_kinds,
)


def _fn(src: str):
    tree = ast.parse(textwrap.dedent(src))
    fn = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)][0]
    return fn, tree


def _first_call(src: str) -> ast.Call:
    return [n for n in ast.walk(ast.parse(textwrap.dedent(src))) if isinstance(n, ast.Call)][0]


# ---------------------------------------------------------------- kind scoping
def test_shell_quote_sanitizes_command_only():
    c = _first_call("shlex.quote(x)")
    assert SinkKind.COMMAND in sanitizer_kinds(c)
    assert SinkKind.SQL not in sanitizer_kinds(c), "must not silence SQL sinks"
    assert SinkKind.PATH not in sanitizer_kinds(c)


def test_html_escape_does_not_sanitize_command():
    c = _first_call("html.escape(x)")
    assert SinkKind.HTML in sanitizer_kinds(c)
    assert SinkKind.COMMAND not in sanitizer_kinds(c)


def test_unknown_call_is_not_a_sanitizer_fail_closed():
    assert sanitizer_kinds(_first_call("mystery(x)")) == frozenset()


def test_shlex_split_is_argv_builder_not_a_sanitizer():
    c = _first_call("shlex.split(x)")
    assert is_argv_builder(c) is True
    assert sanitizer_kinds(c) == frozenset(), "argv-ness is not sanitisation"


# ------------------------------------------------------------- argv / literal
@pytest.mark.parametrize("src,expected", [
    ('subprocess.run(["git", "status"], shell=False)', True),
    ('subprocess.run(shlex.split(cmd), shell=False)', True),
    ('subprocess.run(["sh", "-c", cmd], shell=True)', False),   # shell=True is decisive
    ('subprocess.run(cmd, shell=True)', False),
])
def test_shell_free_argv_detection(src, expected):
    assert call_is_shell_free_argv(_first_call(src)) is expected


def test_literal_command_has_no_parameter_surface():
    assert command_is_fully_literal(_first_call('subprocess.run(["git","status"])'), {"cmd"}) is True
    assert command_is_fully_literal(_first_call('subprocess.run(["git", cmd])'), {"cmd"}) is False


# ------------------------------------------------------------- guard statuses
@pytest.mark.parametrize("label,src,expected", [
    ("unsanitized shell=True", 'def f(cmd):\n    subprocess.run(cmd, shell=True)', "unguarded"),
    ("os.system(param)",       'def f(cmd):\n    os.system(cmd)', "unguarded"),
    ("shlex.quote wrapped",    'def f(cmd):\n    subprocess.run(f"ls {shlex.quote(cmd)}", shell=True)', "guarded"),
    ("argv + shell=False",     'def f(cmd):\n    subprocess.run(shlex.split(cmd), shell=False)', "guarded"),
    ("all-literal command",    'def f():\n    subprocess.run(["git","status"])', "guarded"),
    ("no exec at all",         'def f(x):\n    return x.upper()', "none"),
])
def test_exec_guard_status(label, src, expected):
    fn, tree = _fn(src)
    assert exec_guard_status(fn) == expected, label


def test_one_unguarded_sink_poisons_the_whole_body():
    """A guarded call must not excuse an unguarded one in the same tool."""
    fn, _ = _fn('''
        def f(cmd):
            subprocess.run(["git", "status"])      # safe
            subprocess.run(cmd, shell=True)        # DANGEROUS
    ''')
    assert exec_guard_status(fn) == "unguarded"
