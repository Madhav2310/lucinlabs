"""Lucin Badge Generator — create SVG badges for repos.

Like Snyk's security badges, these show that a project has been
scanned and what its security posture is.

Usage:
    lucin badge ./my-agent/ > badge.svg

Embed in README:
    ![Lucin](./badge.svg)

Badge types:
- "Lucin | passing" (green) — no critical/high findings
- "Lucin | warnings" (yellow) — medium findings only
- "Lucin | failing" (red) — critical/high findings present
- "Lucin | score: 85" — shows numeric security score
"""

from lucin.models import ScanResult
from lucin.scoring import calculate_security_score


def generate_badge_svg(result: ScanResult, style: str = "flat") -> str:
    """Generate an SVG badge based on scan results.

    Args:
        result: Scan result to generate badge for
        style: Badge style ("flat" or "score")

    Returns:
        SVG string
    """
    score = calculate_security_score(result)

    if style == "score":
        return _score_badge(score)

    # Status badge
    if result.critical_count > 0 or result.high_count > 0:
        return _status_badge("failing", "#e05d44")
    elif result.medium_count > 0:
        return _status_badge("warnings", "#dfb317")
    else:
        return _status_badge("passing", "#4c1")


def _status_badge(status: str, color: str) -> str:
    """Generate a shields.io-style status badge."""
    label = "Lucin"
    label_width = len(label) * 6.5 + 10
    value_width = len(status) * 6.5 + 10
    total_width = label_width + value_width

    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="{total_width}" height="20" role="img">
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r">
    <rect width="{total_width}" height="20" rx="3" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#r)">
    <rect width="{label_width}" height="20" fill="#555"/>
    <rect x="{label_width}" width="{value_width}" height="20" fill="{color}"/>
    <rect width="{total_width}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">
    <text x="{label_width/2}" y="14">{label}</text>
    <text x="{label_width + value_width/2}" y="14">{status}</text>
  </g>
</svg>'''


def _score_badge(score: int) -> str:
    """Generate a badge showing the numeric security score."""
    label = "Lucin"
    value = f"score: {score}"

    if score >= 90:
        color = "#4c1"
    elif score >= 70:
        color = "#97ca00"
    elif score >= 50:
        color = "#dfb317"
    elif score >= 25:
        color = "#fe7d37"
    else:
        color = "#e05d44"

    label_width = len(label) * 6.5 + 10
    value_width = len(value) * 6.5 + 10
    total_width = label_width + value_width

    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="{total_width}" height="20" role="img">
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r">
    <rect width="{total_width}" height="20" rx="3" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#r)">
    <rect width="{label_width}" height="20" fill="#555"/>
    <rect x="{label_width}" width="{value_width}" height="20" fill="{color}"/>
    <rect width="{total_width}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">
    <text x="{label_width/2}" y="14">{label}</text>
    <text x="{label_width + value_width/2}" y="14">{value}</text>
  </g>
</svg>'''
