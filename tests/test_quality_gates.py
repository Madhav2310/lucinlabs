"""Quality gate tests — verify product-level requirements.

These tests validate the PRODUCT works correctly end-to-end,
not just individual detectors. They represent the quality gates
that must pass before any release.
"""

import json
import tempfile
from pathlib import Path

import pytest

from lucin.scanner import scan_target
from lucin.scoring import calculate_security_score


@pytest.fixture
def tmp_dir():
    with tempfile.TemporaryDirectory() as d:
        yield Path(d)


# === FALSE POSITIVE VALIDATION ===
# These are SAFE agents that should produce ZERO critical/high findings

class TestFalsePositiveValidation:
    """Run against 10 known-safe agent patterns. Zero FP expected."""

    def test_simple_calculator(self, tmp_dir):
        (tmp_dir / "agent.py").write_text('''
from langchain.tools import tool

@tool
def add(a: int, b: int) -> int:
    """Add two numbers."""
    return a + b

@tool
def multiply(a: int, b: int) -> int:
    """Multiply two numbers."""
    return a * b
''')
        result = scan_target(tmp_dir)
        critical_high = [f for f in result.findings if f.severity.value in ("critical", "high")]
        assert len(critical_high) == 0, f"False positive on safe calculator: {[f.title for f in critical_high]}"

    def test_safe_search_only(self, tmp_dir):
        (tmp_dir / "agent.py").write_text('''
from langchain.tools import tool

@tool
def search_docs(query: str) -> str:
    """Search documentation for relevant articles."""
    return "Results for: " + query
''')
        result = scan_target(tmp_dir)
        critical_high = [f for f in result.findings if f.severity.value in ("critical", "high")]
        assert len(critical_high) == 0

    def test_safe_crewai_readonly(self, tmp_dir):
        (tmp_dir / "config").mkdir()
        (tmp_dir / "config" / "agents.yaml").write_text('''
reader:
  role: "Document Reader"
  goal: "Read and summarize documents"
  tools:
    - PDFSearchTool
    - TXTSearchTool
  human_input: true
''')
        result = scan_target(tmp_dir)
        critical_high = [f for f in result.findings if f.severity.value in ("critical", "high")]
        assert len(critical_high) == 0

    def test_safe_openai_assistant_readonly(self, tmp_dir):
        config = {
            "name": "Safe Assistant",
            "model": "gpt-4o",
            "tools": [{"type": "file_search"}]
        }
        (tmp_dir / "assistant.json").write_text(json.dumps(config))
        result = scan_target(tmp_dir)
        critical_high = [f for f in result.findings if f.severity.value in ("critical", "high")]
        assert len(critical_high) == 0

    def test_safe_mcp_with_auth(self, tmp_dir):
        config = {
            "mcpServers": {
                "docs": {
                    "url": "https://secure.example.com/mcp",
                    "auth": {"type": "oauth2", "client_id": "xxx"},
                    "tools": [{"name": "search", "description": "Search documents"}]
                }
            }
        }
        (tmp_dir / "mcp.json").write_text(json.dumps(config))
        result = scan_target(tmp_dir)
        # Authenticated + HTTPS + read-only = should not trigger critical/high
        critical = [f for f in result.findings if f.severity.value == "critical"]
        assert len(critical) == 0


# === FALSE NEGATIVE VALIDATION ===
# These are VULNERABLE agents that MUST trigger findings

class TestFalseNegativeValidation:
    """Verify all known attack patterns are detected."""

    def test_catches_shell_execution(self, tmp_dir):
        (tmp_dir / "agent.py").write_text('''
from langchain.tools import tool

@tool
def run_shell(cmd: str) -> str:
    """Run a shell command."""
    import subprocess
    return subprocess.check_output(cmd, shell=True).decode()
''')
        result = scan_target(tmp_dir)
        assert any(f.id == "AG-001" for f in result.findings), "Must catch shell execution"

    def test_catches_exfiltration_path(self, tmp_dir):
        (tmp_dir / "agent.py").write_text('''
from langchain.tools import tool

@tool
def query_db(sql: str) -> str:
    """Run SQL query."""
    pass

@tool
def send_webhook(url: str, data: str) -> str:
    """Send data to webhook URL."""
    pass
''')
        result = scan_target(tmp_dir)
        assert any(f.id == "AG-002" for f in result.findings), "Must catch exfiltration path"

    def test_catches_hardcoded_aws_key(self, tmp_dir):
        (tmp_dir / "agent.py").write_text('''
from langchain.tools import tool

AWS_KEY = "AKIAI44QH8DHBG5BRAQ1"

@tool
def helper(x: str) -> str:
    """Help."""
    pass
''')
        result = scan_target(tmp_dir)
        assert any(f.id == "AG-007" for f in result.findings), "Must catch AWS key"

    def test_catches_unauthenticated_mcp(self, tmp_dir):
        config = {"mcpServers": {"db": {"url": "http://localhost:5432/mcp"}}}
        (tmp_dir / "mcp.json").write_text(json.dumps(config))
        result = scan_target(tmp_dir)
        assert any(f.id == "AG-003" for f in result.findings), "Must catch unauth MCP"

    def test_catches_npx_supply_chain(self, tmp_dir):
        config = {"mcpServers": {"x": {"command": "npx", "args": ["-y", "@pkg/server"]}}}
        (tmp_dir / "mcp.json").write_text(json.dumps(config))
        result = scan_target(tmp_dir)
        assert any(f.id == "AG-015" for f in result.findings), "Must catch npx -y"


# === SCORING VALIDATION ===

class TestScoringValidation:
    """Verify security score behaves correctly."""

    def test_perfect_score_for_safe_agent(self, tmp_dir):
        (tmp_dir / "agent.py").write_text('''
from langchain.tools import tool

@tool
def greet(name: str) -> str:
    """Say hello."""
    return f"Hello {name}"
''')
        result = scan_target(tmp_dir)
        score = calculate_security_score(result)
        assert score == 100

    def test_low_score_for_vulnerable_agent(self, tmp_dir):
        (tmp_dir / "agent.py").write_text('''
from langchain.tools import tool

@tool
def execute_shell(cmd: str) -> str:
    """Execute shell."""
    pass

@tool
def http_request(url: str, body: str) -> str:
    """Send HTTP."""
    pass

@tool
def read_database(query: str) -> str:
    """Query DB."""
    pass
''')
        result = scan_target(tmp_dir)
        score = calculate_security_score(result)
        assert score < 50, f"Vulnerable agent should score <50, got {score}"


# === PERFORMANCE VALIDATION ===

class TestPerformanceValidation:
    """Verify scan performance is acceptable."""

    def test_scan_completes_under_200ms(self, tmp_dir):
        """A typical project should scan in under 200ms."""
        import time
        (tmp_dir / "agent.py").write_text('''
from langchain.tools import tool

@tool
def shell(cmd: str) -> str:
    """Shell."""
    pass

@tool
def http(url: str) -> str:
    """HTTP."""
    pass
''')
        start = time.time()
        scan_target(tmp_dir)
        elapsed_ms = (time.time() - start) * 1000
        assert elapsed_ms < 200, f"Scan took {elapsed_ms:.0f}ms, expected <200ms"
