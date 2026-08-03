"""Calibration for the security score curve.

The score must never floor to an indistinguishable 0 for realistic scans —
that was the bug in the old flat-subtraction formula: any scan whose
weighted penalty crossed 100 (as few as 4 CRITICAL findings alone) read the
same as a scan ten times worse. These values are the exact numbers reviewed
and approved before shipping the new formula; if the constant changes,
update this table deliberately, not by loosening the assertions.
"""

from unittest.mock import MagicMock

from lucin.models import Finding, Severity
from lucin.scoring import calculate_security_score


def _result(critical=0, high=0, medium=0, low=0):
    findings = (
        [Finding(id="C", title="C", severity=Severity.CRITICAL, description="")] * critical
        + [Finding(id="H", title="H", severity=Severity.HIGH, description="")] * high
        + [Finding(id="M", title="M", severity=Severity.MEDIUM, description="")] * medium
        + [Finding(id="L", title="L", severity=Severity.LOW, description="")] * low
    )
    result = MagicMock()
    result.findings = findings
    return result


def test_clean_scan_is_100():
    assert calculate_security_score(_result()) == 100


def test_never_floors_to_zero_for_realistic_scans():
    """The bug this fixes: distinct bad scans must produce distinct scores."""
    real = calculate_security_score(_result(critical=4, high=4, medium=25))
    twice = calculate_security_score(_result(critical=8, high=8, medium=50))
    four_times = calculate_security_score(_result(critical=16, high=16, medium=100))

    assert real > 0, "a realistic 4-critical scan must not floor to 0"
    assert real > twice > four_times, "worse scans must score strictly lower"


def test_calibration_table():
    """Reviewed numbers — see the module docstring before changing these."""
    cases = {
        (0, 0, 0, 0): 100,
        (0, 0, 1, 0): 90,
        (0, 1, 0, 0): 82,
        (1, 0, 0, 0): 74,
        (2, 0, 0, 0): 58,
        (3, 0, 0, 0): 48,
        (4, 0, 0, 0): 41,
        (4, 4, 25, 0): 16,
    }
    for (c, h, m, low), expected in cases.items():
        got = calculate_security_score(_result(critical=c, high=h, medium=m, low=low))
        assert got == expected, f"critical={c} high={h} medium={m} low={low}: expected {expected}, got {got}"
