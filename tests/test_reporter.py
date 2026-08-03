from unittest.mock import MagicMock

from rich.console import Console

from lucin.models import Finding, Severity
from lucin.reporter import _print_triage_table


def _finding(severity, rule_id, tool_name="", source_file="", source_line=0):
    return Finding(
        id=rule_id, title=rule_id, severity=severity, description="",
        tool_name=tool_name, source_file=source_file, source_line=source_line,
    )


def test_triage_table_lists_every_finding():
    """Every finding must appear as a row, and the counts line must match the severity mix."""
    findings = [
        _finding(Severity.CRITICAL, "AG-001", tool_name="execute_shell", source_file="agent.py", source_line=9),
        _finding(Severity.HIGH, "AG-011", tool_name="search_web"),
        _finding(Severity.HIGH, "AG-011", tool_name="send_email"),
        _finding(Severity.MEDIUM, "AG-006"),
        _finding(Severity.LOW, "AG-999"),
    ]
    result = MagicMock()
    result.critical_count = 1
    result.high_count = 2
    result.medium_count = 1
    result.low_count = 1
    result.findings = findings

    console = Console(width=100, record=True)
    _print_triage_table(console, result)
    output = console.export_text()

    assert "1 critical" in output
    assert "2 high" in output
    assert "1 medium" in output
    assert "1 low" in output
    # every finding's rule id is a row
    for f in findings:
        assert f.id in output
    assert "execute_shell" in output
    assert "agent.py:9" in output


def test_triage_table_sorted_by_severity():
    """Rows must be ordered critical -> high -> medium -> low, matching the panels below."""
    findings = [
        _finding(Severity.LOW, "AG-LOW"),
        _finding(Severity.CRITICAL, "AG-CRIT"),
        _finding(Severity.MEDIUM, "AG-MED"),
        _finding(Severity.HIGH, "AG-HIGH"),
    ]
    result = MagicMock()
    result.critical_count = 1
    result.high_count = 1
    result.medium_count = 1
    result.low_count = 1
    result.findings = findings

    console = Console(width=100, record=True)
    _print_triage_table(console, result)
    output = console.export_text()

    order = [output.index(rid) for rid in ("AG-CRIT", "AG-HIGH", "AG-MED", "AG-LOW")]
    assert order == sorted(order), "table rows are not sorted critical -> high -> medium -> low"
