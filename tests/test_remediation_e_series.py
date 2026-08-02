"""Regression tests for the SCAN-engine remediation (plan/70 §E1,E2,E3,E7,E8,H4).

Each test locks in a specific correctness fix so the defect cannot silently
return. Precision is sacred: the FP-class tests assert NON-firing.
"""

import tempfile
from pathlib import Path

import pytest

from lucin.scanner import scan_target
from lucin.detectors import (
    PER_AGENT_DETECTORS, CROSS_AGENT_DETECTORS, run_all_detectors,
)
from lucin.models import Agent, Tool, ToolCapability


def _scan_src(src: str, name: str = "agent.py"):
    d = Path(tempfile.mkdtemp())
    p = d / name
    p.write_text(src)
    return scan_target(p)


# ---------------------------------------------------------------------------
# E1 — crash isolation
# ---------------------------------------------------------------------------
class TestE1CrashIsolation:
    def test_scan_survives_malformed_file(self):
        """A malformed .mcp.json (non-dict `headers`) must not abort the scan —
        the rest of the repo still scans and findings still come back."""
        d = Path(tempfile.mkdtemp())
        # Malformed MCP config: `headers` is a list, not a dict (the confirmed
        # crash shape at mcp_parser _parse_server_entry).
        (d / ".mcp.json").write_text(
            '{"mcpServers": {"x": {"url": "http://h", "headers": ["oops"]}}}'
        )
        # A perfectly good vulnerable agent alongside it.
        (d / "agent.py").write_text(
            "from langchain.tools import tool\n"
            "import subprocess\n"
            "@tool\n"
            "def run(cmd: str):\n"
            "    '''Run a shell command.'''\n"
            "    subprocess.run(cmd, shell=True)\n"
        )
        result = scan_target(d)  # must NOT raise
        ids = {f.id for f in result.findings}
        assert ids, "malformed file aborted the scan (0 findings on a vuln repo)"

    def test_detector_crash_is_isolated_and_recorded(self):
        """One raising detector must not sink the others; error is a diagnostic."""
        def boom(agent):
            raise RuntimeError("kaboom")

        agent = Agent(name="a", tools=[Tool(name="run",
                      capabilities=[ToolCapability.EXECUTE_CODE])])
        diags: list[str] = []
        # Temporarily inject a crashing detector.
        PER_AGENT_DETECTORS.append(boom)
        try:
            findings = run_all_detectors([agent], diagnostics=diags)
        finally:
            PER_AGENT_DETECTORS.remove(boom)
        assert any("boom" in d and "kaboom" in d for d in diags)
        # Other detectors still produced findings (shell exec agent).
        assert findings is not None


# ---------------------------------------------------------------------------
# E2 — async blindness
# ---------------------------------------------------------------------------
class TestE2Async:
    def test_async_sql_tool_detected(self):
        src = (
            "from langchain.tools import tool\n"
            "from sqlalchemy import text, create_engine\n"
            "@tool\n"
            "async def sql_engine(query: str) -> str:\n"
            "    '''Run a SQL query.'''\n"
            "    con = create_engine('sqlite://').connect()\n"
            "    return str(con.execute(text(query)))\n"
        )
        assert "AG-SQL" in {f.id for f in _scan_src(src).findings}

    def test_async_docker_tool_detected(self):
        src = (
            "from langchain.tools import tool\n"
            "import subprocess\n"
            "@tool\n"
            "async def sandbox(image: str):\n"
            "    '''Run in a container.'''\n"
            "    subprocess.run(['docker', 'run', '--privileged', image])\n"
        )
        assert "AG-DOCKER-EXEC" in {f.id for f in _scan_src(src).findings}

    def test_async_matches_sync(self):
        base = (
            "from langchain.tools import tool\n"
            "from sqlalchemy import text, create_engine\n"
            "@tool\n"
            "{kw}def sql_engine(query: str) -> str:\n"
            "    '''Run a SQL query.'''\n"
            "    con = create_engine('sqlite://').connect()\n"
            "    return str(con.execute(text(query)))\n"
        )
        sync = {f.id for f in _scan_src(base.format(kw=""), "sync.py").findings}
        asyn = {f.id for f in _scan_src(base.format(kw="async "), "asy.py").findings}
        assert "AG-SQL" in sync and "AG-SQL" in asyn


# ---------------------------------------------------------------------------
# E3 — substring / greedy-regex FP-FN class
# ---------------------------------------------------------------------------
class TestE3Substring:
    def test_send_to_search_queue_is_egress(self):
        from lucin.aifg import is_egress_by_name
        # Contains '_search' but is a SEND — must classify as egress (FN fix).
        assert is_egress_by_name("send_to_search_queue", has_network=True) is True
        # Genuine fetch tools remain non-egress.
        assert is_egress_by_name("web_search", has_network=True) is False
        assert is_egress_by_name("fetch_results", has_network=True) is False

    def test_sql_receiver_c_no_endswith_overmatch(self):
        from lucin.detectors.sql_injection import _is_db_receiver
        assert _is_db_receiver("c") is True         # bare cursor
        assert _is_db_receiver("_session") is True  # boundary suffix
        assert _is_db_receiver("src") is False      # was FP via .endswith('c')
        assert _is_db_receiver("logic") is False

    def test_cors_regex_no_cross_statement_fp(self):
        from lucin.detectors.agent_server import _has_wildcard_cors
        # A safe explicit origin, with an unrelated ['*'] list elsewhere — the old
        # greedy DOTALL regex fired across statements; the AST check must not.
        safe = 'allow_origins=["https://app.example.com"]\nGLOB = ["*"]\n'
        assert _has_wildcard_cors(safe) is False
        assert _has_wildcard_cors('allow_origins=["*"]') is True

    def test_scope_path_token_boundary(self):
        from lucin.detectors.scope_violation import _arg_grants_sensitive_path
        assert _arg_grants_sensitive_path("/Users/dev/.ssh", "~/.ssh") is True
        assert _arg_grants_sensitive_path("/etc/passwd", "/etc/passwd") is True
        # '.env' → 'env' must not match inside 'environment' (FP fix).
        assert _arg_grants_sensitive_path("/srv/environment", "~/.env") is False


# ---------------------------------------------------------------------------
# E7 — de-duplication of subsumed exfil findings
# ---------------------------------------------------------------------------
class TestE7Dedup:
    def test_three_tool_agent_yields_one_primary(self):
        src = (
            "from langchain.tools import tool\n"
            "import requests\n"
            "@tool\n"
            "def web_fetch(url: str) -> str:\n"
            "    '''Fetch a web page.'''\n"
            "    return requests.get(url).text\n"
            "@tool\n"
            "def read_credentials(path: str) -> str:\n"
            "    '''Read the secrets/credentials file.'''\n"
            "    return open(path).read()\n"
            "@tool\n"
            "def send_email(to: str, body: str):\n"
            "    '''Send an email.'''\n"
            "    requests.post('https://mail.example.com', json={'b': body})\n"
        )
        findings = _scan_src(src).findings
        exfil = [f for f in findings
                 if f.id in ("AG-TRIFECTA", "AG-002")
                 or (f.id == "AG-COMP" and "Lateral" in f.title)]
        assert len(exfil) == 1, f"expected 1 primary exfil finding, got {len(exfil)}"
        assert exfil[0].id == "AG-TRIFECTA"  # most specific wins
        assert "Subsumes" in exfil[0].description


# ---------------------------------------------------------------------------
# E8 — detector precision tail
# ---------------------------------------------------------------------------
class TestE8Tail:
    def test_localhost_real_db_creds_not_suppressed(self):
        from lucin.detectors.secrets import _is_false_positive
        # Real creds on localhost:5432 must NOT be treated as a benign default.
        assert _is_false_positive(
            "postgresql://admin:S3cretPass@localhost:5432/prod") is False
        # Documented dev default still suppressed.
        assert _is_false_positive(
            "postgresql://postgres:postgres@localhost:5432/db") is True

    def test_mcp_server_convention_not_typosquat(self):
        from lucin.detectors.supply_chain import detect_typosquatting
        # Legit community convention — must not be flagged.
        assert detect_typosquatting("mcp-server-weather")[0] is False
        # A genuine 1-char typo is still caught.
        assert detect_typosquatting("mcp-server-githb")[0] is True

    def test_generic_file_writer_not_self_modification(self):
        src = (
            "from langchain.tools import tool\n"
            "@tool\n"
            "def save_report(path: str, content: str):\n"
            "    '''Write a report to disk.'''\n"
            "    open(path, 'w').write(content)\n"
        )
        own = [f for f in _scan_src(src).findings
               if f.id == "AG-023" and "Own Source" in f.title]
        assert own == []

    def test_self_writer_is_self_modification(self):
        src = (
            "from langchain.tools import tool\n"
            "@tool\n"
            "def rewrite(content: str):\n"
            "    '''Rewrite behavior.'''\n"
            "    open(__file__, 'w').write(content)\n"
        )
        own = [f for f in _scan_src(src).findings
               if f.id == "AG-023" and "Own Source" in f.title]
        assert own, "self-referential (__file__) write should flag AG-023"


# ---------------------------------------------------------------------------
# H4 — no registered detector is a no-op
# ---------------------------------------------------------------------------
class TestH4Registry:
    def test_no_registered_detector_returns_empty_stub(self):
        """Every registered detector must be capable of firing — the disabled
        no-op detectors (memory_poisoning `return []`) are NOT registered."""
        import lucin.detectors as det
        from lucin.detectors.memory_poisoning import detect_memory_poisoning
        assert detect_memory_poisoning not in PER_AGENT_DETECTORS
        assert detect_memory_poisoning not in CROSS_AGENT_DETECTORS
        # The registry count is non-zero and matches the exported constant.
        assert det.ACTIVE_DETECTOR_COUNT == (
            len(PER_AGENT_DETECTORS) + len(CROSS_AGENT_DETECTORS))
        assert det.ACTIVE_DETECTOR_COUNT > 0

    def test_scan_metadata_counts_derive_from_registry(self):
        import lucin.detectors as det
        result = _scan_src(
            "from langchain.tools import tool\n"
            "@tool\n"
            "def t(x: str):\n"
            "    '''do.'''\n"
            "    return x\n"
        )
        md = result.metadata
        assert md.detection_rules_active == det.ACTIVE_DETECTOR_COUNT
        assert md.secret_patterns_active > 0
        assert md.injection_patterns_active > 0
