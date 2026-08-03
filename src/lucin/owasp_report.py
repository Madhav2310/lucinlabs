"""OWASP ASI coverage report for a scan result.

Shows which of the OWASP Top 10 for Agentic Applications (ASI01-ASI10)
are covered by active detectors, which were triggered in this scan,
and which are not yet covered — honest about gaps.

Blueprint §4.4: "the detection catalog mapped to OWASP ASI."
"""

from __future__ import annotations

from lucin.models import ScanResult
from lucin.owasp import ASI, RULE_TO_ASI

# Full OWASP ASI taxonomy — single source of truth in lucin.owasp.
ASI_DESCRIPTIONS = ASI

# Which ASI items each detector covers (static — regardless of what fires).
DETECTOR_COVERAGE: dict[str, list[str]] = {
    rule_id: list(asi_codes) for rule_id, asi_codes in RULE_TO_ASI.items()
}


def coverage_report(result: ScanResult) -> dict:
    """Return a structured coverage report for the scan result.

    Returns:
      covered_by_detectors: ASI IDs covered by at least one active detector
      triggered_in_scan:    ASI IDs that fired at least one finding
      not_covered:          ASI IDs with no active detector
      gap_analysis:         human-readable notes per uncovered ASI
    """
    all_asi = set(ASI_DESCRIPTIONS.keys())

    # What detectors cover (static)
    covered = set()
    for asi_list in DETECTOR_COVERAGE.values():
        covered.update(asi_list)

    # What actually fired in this scan
    triggered: set[str] = set()
    for finding in result.findings:
        triggered.update(finding.owasp_asi)

    not_covered = all_asi - covered

    # Gap notes shown only for truly uncovered ASI categories.
    # All 10 ASI categories now have at least one detector — this dict may be empty.
    # If a category re-opens a gap (detector disabled), add it here with honest reasoning.
    gap_notes: dict[str, str] = {}

    return {
        "covered_by_detectors": sorted(covered),
        "triggered_in_scan":    sorted(triggered),
        "not_covered":          sorted(not_covered),
        "coverage_pct":         round(len(covered) / len(all_asi) * 100),
        "gap_analysis":         {k: gap_notes.get(k, "No active detector.") for k in not_covered},
    }


def format_coverage_report(result: ScanResult) -> str:
    """Format the coverage report for terminal output."""
    report = coverage_report(result)
    lines = []
    lines.append("OWASP ASI Coverage")
    lines.append(f"  {report['coverage_pct']}% of OWASP ASI Top 10 covered by active detectors")
    lines.append("")

    for asi, desc in sorted(ASI_DESCRIPTIONS.items()):
        covered  = asi in report["covered_by_detectors"]
        fired    = asi in report["triggered_in_scan"]
        if fired:
            icon = "🟢"
        elif covered:
            icon = "🟡"
        else:
            icon = "⬜"
        lines.append(f"  {icon} {asi}: {desc}")
        if asi in report["gap_analysis"] and not covered:
            lines.append(f"       ↳ Gap: {report['gap_analysis'][asi]}")

    lines.append("")
    lines.append("  🟢 = fired in this scan   🟡 = covered, not triggered   ⬜ = not covered")
    return "\n".join(lines)
