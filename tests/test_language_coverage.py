"""A scan that read nothing must not report a verdict.

WHY THIS TEST EXISTS
--------------------
Lucin enumerates only `*.py`, `*.json`, shell and `SKILL.md`. A Rust, Go, Java,
C# or TypeScript agent therefore produces zero candidate files — and used to
render as:

    SECURITY SCORE:  ████████████████████  100/100 — Excellent
    ✅ Clean Scan — No security findings detected.
    Show it: lucin badge . --style score  →  drops an SVG for your README.

...on an agent containing `Command::new("sh").arg("-c").arg(user_cmd)` and a
hardcoded `sk-proj-` key. `lucin scan --ci --fail-on high` exited 0 on it.

That is an affirmative false assurance, and it was the default on every language
we do not parse. It is also the scan-level counterpart of the finding-level
evidence gate: *a finding nobody can check must not be CRITICAL*, therefore
**a scan that examined nothing must not score 100**.

The fix is not "parse more languages" — agent frameworks are overwhelmingly
Python and TypeScript, and chasing Rust/Java/C# parsers is the treadmill that
turns an agent scanner into a mediocre general-purpose SAST. The fix is to never
claim a verdict we did not earn, which covers every present and future language
at once.

WHAT MUST NOT REGRESS
    * unsupported-only target -> `analysed_nothing`, NOT-ANALYSED panel, --ci exit 2
    * a single Cargo.toml / README.md must NOT count as "analysed" (it would let
      one manifest defeat the whole gate — this was the first implementation's bug)
    * supported targets keep scoring normally, with a coverage line
"""
import textwrap
from pathlib import Path

import pytest

from lucin.scanner import scan_target

RUST_AGENT = """\
use std::process::Command;
const OPENAI_API_KEY: &str = "sk-proj-abc123def456ghi789jkl012mno345pqr";
fn run_tool(user_cmd: &str) -> String {
    let out = Command::new("sh").arg("-c").arg(user_cmd).output().unwrap();
    String::from_utf8_lossy(&out.stdout).to_string()
}
"""

PY_AGENT = """\
from langchain.tools import tool
import subprocess

@tool
def run(cmd: str) -> str:
    \"\"\"Run a command.\"\"\"
    return subprocess.check_output(cmd, shell=True).decode()
"""


def test_unsupported_language_is_not_a_clean_scan(tmp_path):
    """A Rust agent must be UNKNOWN, never clean."""
    (tmp_path / "main.rs").write_text(RUST_AGENT)
    meta = scan_target(tmp_path).metadata
    assert meta.analysed_nothing, (
        "A Rust-only target reported itself as analysed. It would render "
        "100/100 Excellent on an agent with a live command injection."
    )
    assert meta.files_analysed == 0
    assert meta.unsupported_extensions.get(".rs") == 1


@pytest.mark.parametrize("filename,content", [
    ("agent.ts", "import { exec } from 'child_process';\nexec(cmd);\n"),
    ("Agent.java", "public class Agent { void f(){ Runtime.getRuntime().exec(c); } }"),
    ("Agent.cs", "class Agent { void F(){ Process.Start(c); } }"),
    ("server.go", "package main\nimport \"os/exec\"\nfunc f(){ exec.Command(c) }"),
])
def test_every_unsupported_agent_language_is_flagged(tmp_path, filename, content):
    """TypeScript, Java, C# and Go must all refuse to produce a verdict.

    TypeScript matters most: it is co-Tier-1 with Python in the MCP ecosystem
    (both SDKs past 1B downloads), and `docs/limits.md` previously implied regex
    support that does not exist — `.ts` files are never enumerated at all.
    """
    (tmp_path / filename).write_text(content)
    assert scan_target(tmp_path).metadata.analysed_nothing, (
        f"{filename} produced a scannable verdict but nothing was parsed"
    )


def test_a_lone_manifest_does_not_count_as_analysis(tmp_path):
    """Cargo.toml / README.md must not defeat the gate.

    The first implementation counted `.toml`, `.md` and `.yaml` as analysable, so
    a Rust project reported itself analysed on the strength of its Cargo.toml and
    the NOT-ANALYSED panel never fired. Coverage compares source code we can read
    against source code we cannot; config and documentation are neither.
    """
    (tmp_path / "main.rs").write_text(RUST_AGENT)
    (tmp_path / "Cargo.toml").write_text("[package]\nname = \"agent\"\n")
    (tmp_path / "README.md").write_text("# Agent\nDocs.\n")
    meta = scan_target(tmp_path).metadata
    assert meta.analysed_nothing, (
        "A Cargo.toml/README.md was counted as analysis — one manifest must not "
        "be able to defeat the unsupported-language gate."
    )


def test_supported_target_still_scores_normally(tmp_path):
    """The gate must not fire on a real Python agent."""
    (tmp_path / "agent.py").write_text(PY_AGENT)
    meta = scan_target(tmp_path).metadata
    assert not meta.analysed_nothing
    assert meta.files_analysed == 1
    assert meta.unsupported_extensions == {}


def test_polyglot_repo_reports_what_it_skipped(tmp_path):
    """A Python agent beside 200 Rust files must still say what it ignored.

    Silent under-coverage is the worst failure mode for a security tool: a false
    positive costs ten minutes, an unexamined file costs a breach.
    """
    (tmp_path / "agent.py").write_text(PY_AGENT)
    src = tmp_path / "src"
    src.mkdir()
    for i in range(200):
        (src / f"mod{i}.rs").write_text(RUST_AGENT)

    meta = scan_target(tmp_path).metadata
    assert not meta.analysed_nothing, "one supported file means we did analyse something"
    assert meta.files_analysed == 1
    assert meta.unsupported_extensions.get(".rs") == 200
    assert meta.files_total == 201


def test_mcp_config_is_analysed_regardless_of_server_language(tmp_path):
    """MCP config is our cross-language surface and must never be gated out.

    A Go or Rust MCP server's implementation is invisible to us, but its WIRING —
    overprivilege, unpinned `npx -y`, leaked tokens, filesystem-root grants — is
    JSON, and that is where most MCP risk lives.
    """
    (tmp_path / ".mcp.json").write_text(textwrap.dedent("""\
        {"mcpServers": {"fs": {"command": "npx",
          "args": ["-y", "@modelcontextprotocol/server-filesystem", "/"],
          "env": {"GITHUB_TOKEN": "ghp_abcdefghijklmnopqrstuvwxyz0123456789"}}}}
    """))
    result = scan_target(tmp_path)
    assert not result.metadata.analysed_nothing
    assert result.findings, "MCP config produced no findings"
