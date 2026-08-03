"""Agent Security Score — a single number (0-100) summarizing agent security posture."""

from lucin.models import ScanResult, Severity

# Weight of each severity level in the score calculation
SEVERITY_WEIGHTS = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 15,
    Severity.MEDIUM: 8,
    Severity.LOW: 3,
    Severity.INFO: 0,
}

# Decay constant for the score curve — see calculate_security_score.
_DECAY = 70


def calculate_security_score(result: ScanResult) -> int:
    """Calculate security score from 0 (terrible) to 100 (no findings).

    Scoring logic:
    - Each finding contributes a weighted penalty (CRITICAL 25, HIGH 15,
      MEDIUM 8, LOW 3) — same weights as before.
    - score = 100 * DECAY / (DECAY + total_weighted_penalty)

    This used to be a flat 100-minus-penalty, floored at 0. That formula
    made any scan whose weighted penalty reached 100 — as few as 4 CRITICAL
    findings alone, or a realistic mix like 4 CRITICAL + 4 HIGH + 25 MEDIUM —
    read as an indistinguishable 0. A repo with 4 critical findings and one
    with 40 both showed the same number, so the score stopped carrying
    information exactly where it mattered most: telling "bad" apart from
    "much worse."

    The hyperbolic form here never truly floors — it only approaches 0 as
    the weighted penalty grows, so scores keep differentiating regardless of
    scale (see tests/test_scoring.py for calibration examples), while still
    landing 1-3 finding scans in roughly the same bands the old linear
    formula did.

    A score of:
    - 90-100: Excellent (no critical/high findings)
    - 70-89:  Good (minor issues)
    - 50-69:  Concerning (significant gaps)
    - 25-49:  Poor (serious vulnerabilities)
    - 0-24:   Critical (immediate action required)
    """
    weighted = sum(SEVERITY_WEIGHTS.get(f.severity, 0) for f in result.findings)
    return round(100 * _DECAY / (_DECAY + weighted))


def score_label(score: int) -> str:
    """Get human-readable label for a score."""
    if score >= 90:
        return "Excellent"
    elif score >= 70:
        return "Good"
    elif score >= 50:
        return "Concerning"
    elif score >= 25:
        return "Poor"
    else:
        return "Critical"


def score_color(score: int) -> str:
    """Get rich color string for a score."""
    if score >= 90:
        return "bold green"
    elif score >= 70:
        return "green"
    elif score >= 50:
        return "yellow"
    elif score >= 25:
        return "bold yellow"
    else:
        return "bold red"
