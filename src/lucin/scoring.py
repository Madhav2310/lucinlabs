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

# Maximum penalty (the score can't go below 0)
MAX_PENALTY = 100


def calculate_security_score(result: ScanResult) -> int:
    """Calculate security score from 0 (terrible) to 100 (no findings).

    Scoring logic:
    - Start at 100 (perfect)
    - Deduct points per finding based on severity
    - Each CRITICAL deducts 25 points
    - Each HIGH deducts 15 points
    - Each MEDIUM deducts 8 points
    - Each LOW deducts 3 points
    - Floor at 0

    A score of:
    - 90-100: Excellent (no critical/high findings)
    - 70-89:  Good (minor issues)
    - 50-69:  Concerning (significant gaps)
    - 25-49:  Poor (serious vulnerabilities)
    - 0-24:   Critical (immediate action required)
    """
    score = 100

    for finding in result.findings:
        penalty = SEVERITY_WEIGHTS.get(finding.severity, 0)
        score -= penalty

    return max(0, score)


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
