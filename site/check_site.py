#!/usr/bin/env python3
"""check_site.py — reproducible gate for the website.

Everything else in this project ships with the command that verifies it; the site
should not be the exception. This checks the things that were ACTUALLY broken in the
first landing build (measured 2026-07-30):

  * no meta description / canonical / Open Graph / Twitter card / JSON-LD
    -> a shared link previewed as a bare URL
  * render-blocking third-party font CDN (fonts.googleapis.com) -> LCP cost
  * three dead primary CTAs (href="#")
  * copy promising a "free trial" and GA "runtime access" that do not exist
  * a sitemap listing pages that do not exist (advertising 404s)

Usage:  python site/check_site.py          # exit 1 on any failure
        python site/check_site.py --list   # show what would be checked
"""
from __future__ import annotations

import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

SITE = Path(__file__).resolve().parent

REQUIRED_META = [
    ('meta name="description"', r'<meta\s+name="description"\s+content="[^"]{60,}"'),
    ("canonical", r'<link\s+rel="canonical"\s+href="https?://[^"]+"'),
    ("og:title", r'<meta\s+property="og:title"'),
    ("og:description", r'<meta\s+property="og:description"'),
    ("og:image", r'<meta\s+property="og:image"'),
    ("og:url", r'<meta\s+property="og:url"'),
    ("twitter:card", r'<meta\s+name="twitter:card"\s+content="summary_large_image"'),
    ("JSON-LD", r'<script\s+type="application/ld\+json"'),
    ("html lang", r"<html[^>]+lang="),
]

# Copy that promises something we do not have. Keeps the site consistent with
# tools/claim_audit.py, which guards the docs but never covered the landing page.
BANNED_COPY = [
    (r"free trial", "no billing exists; do not promise a trial"),
    (r"get runtime access(?!\s*[:(])", "runtime is design-partner preview, not GA"),
    (r"\b(?:enterprise[- ]grade|military[- ]grade|bank[- ]grade)\b", "unverifiable puffery"),
    (r"100%\s*(?:accurate|secure|coverage)", "absolute claim we cannot support"),
    (r"0%\s*false[- ]positive", "must carry the 'adjudicated' qualifier"),
]

BLOCKING_THIRD_PARTY = [
    r'<link[^>]+href="https?://fonts\.googleapis\.com',
    r'<script(?![^>]*\basync\b)(?![^>]*\bdefer\b)[^>]+src="https?://(?!lucin\.security)',
]


def _html_files() -> list[Path]:
    return sorted(p for p in SITE.rglob("*.html") if ".git" not in p.parts)


def check_page(path: Path) -> list[str]:
    errs: list[str] = []
    html = path.read_text(errors="replace")
    rel = path.relative_to(SITE)

    for label, pattern in REQUIRED_META:
        if not re.search(pattern, html, re.I):
            errs.append(f"{rel}: missing {label}")

    # JSON-LD must actually parse — an invalid blob is silently ignored by crawlers.
    for m in re.finditer(r'<script\s+type="application/ld\+json"[^>]*>(.*?)</script>',
                         html, re.S | re.I):
        try:
            json.loads(m.group(1))
        except json.JSONDecodeError as e:
            errs.append(f"{rel}: JSON-LD does not parse ({e})")

    dead = len(re.findall(r'href="#"', html))
    if dead:
        errs.append(f"{rel}: {dead} dead link(s) href=\"#\"")

    for pattern in BLOCKING_THIRD_PARTY:
        if re.search(pattern, html, re.I):
            errs.append(f"{rel}: render-blocking third-party resource ({pattern[:40]}…)")

    # Strip tags before scanning copy so an href or class name cannot trip a rule.
    text = re.sub(r"<[^>]+>", " ", html)
    for pattern, why in BANNED_COPY:
        for m in re.finditer(pattern, text, re.I):
            frag = text[max(0, m.start() - 40):m.end() + 40].strip().replace("\n", " ")
            errs.append(f"{rel}: banned copy /{pattern}/ — {why}\n      … {frag} …")

    if not re.search(r'<img[^>]+alt=|<svg[^>]+role="img"|aria-label=', html, re.I):
        errs.append(f"{rel}: no alt text / aria-label found (accessibility)")
    errs += check_paired_metrics(rel, html)
    return errs


# A page may not cite the FLATTERING precision figure without the unflattering one.
# The first landing build led with "0 confirmed false positives … 52 real repos" while
# PROGRESS.md recorded 58% (95% CI 32-81%) on the broad population — a reader who
# opened the repo would find a number the page had hidden. That is the hostile-reader
# failure our own anti-slop rules exist to prevent, so it is now a gate, not a habit.
# The lookbehind matters: without it this matched the trailing zero of "150 false
# positives out of 330" (a figure we quote about someone else's tool) and demanded we
# pair it with our own precision number. A precision gate with a precision bug — the
# same "no word boundary" error class this project keeps finding in its own detectors.
_FAVOURABLE_FP = re.compile(r"(?<![\d.])0\s*(?:adjudicated|confirmed)?\s*false[- ]positive", re.I)
_BROAD_PRECISION = re.compile(r"\b\d{1,3}(?:\.\d+)?\s*%\s*precision|precision[^.]{0,60}\bCI\b", re.I)

# 2026-07-30: broad-population precision was WITHDRAWN (it was computed over the same
# adjudication labels used to build the precision filters — train-on-test). That made the
# pairing rule unsatisfiable: a page could no longer cite the favourable 0-FP result at all,
# because the unfavourable figure it had to be paired with no longer exists.
#
# The rule's PURPOSE is that a reader never meets the flattering number alone. An explicit
# withdrawal satisfies that purpose better than a figure does — it discloses that we do not
# currently know our precision. So a withdrawal counts as the paired disclosure, and any
# page that states a precision PERCENTAGE still needs an interval.
_WITHDRAWN = re.compile(
    r"precision[^.]{0,80}(withdraw|being re-measured|re-measurement|not measured)"
    r"|(withdraw|being re-measured|re-measurement|not measured)[^.]{0,80}precision", re.I)


def check_paired_metrics(path: Path, html: str) -> list[str]:
    text = re.sub(r"<[^>]+>", " ", html)
    if not _FAVOURABLE_FP.search(text):
        return []
    errs = []
    withdrawn = bool(_WITHDRAWN.search(text))
    if not _BROAD_PRECISION.search(text) and not withdrawn:
        errs.append(f"{path}: cites the 0-false-positive result without either the "
                    f"broad-population precision figure or an explicit withdrawal "
                    f"(unpaired favourable metric)")
    # An interval is required only when an actual percentage is asserted. "Withdrawn"
    # is not a point estimate, so demanding a CI for it is nonsense.
    asserts_pct = re.search(r"\b\d{1,3}(?:\.\d+)?\s*%\s*precision", text, re.I)
    if asserts_pct and "CI" not in text and "confidence interval" not in text.lower():
        errs.append(f"{path}: precision claim without a confidence interval")
    return errs


def check_sitemap() -> list[str]:
    """Every sitemap URL must map to a file that exists — never advertise a 404."""
    sm = SITE / "sitemap.xml"
    if not sm.exists():
        return ["sitemap.xml missing"]
    errs: list[str] = []
    try:
        root = ET.fromstring(sm.read_text())
    except ET.ParseError as e:
        return [f"sitemap.xml does not parse: {e}"]
    ns = {"s": "http://www.sitemap.org/schemas/sitemap/0.9"}
    locs = [e.text.strip() for e in root.findall(".//s:loc", ns)] or \
           [e.text.strip() for e in root.iter() if e.tag.endswith("loc") and e.text]
    for loc in locs:
        path = loc.split("lucin.security", 1)[-1].strip("/")
        candidates = [SITE / "index.html"] if not path else [
            SITE / path / "index.html", SITE / f"{path}.html", SITE / path]
        if not any(c.exists() for c in candidates):
            errs.append(f"sitemap advertises a page that does not exist: /{path}/")
    return errs


def main(argv: list[str]) -> int:
    pages = _html_files()
    if "--list" in argv:
        print(f"pages: {[str(p.relative_to(SITE)) for p in pages]}")
        print(f"checks/page: {len(REQUIRED_META)} meta + JSON-LD + dead-links + "
              f"blocking-3p + {len(BANNED_COPY)} copy rules + a11y")
        return 0

    errs: list[str] = []
    for p in pages:
        errs += check_page(p)
    errs += check_sitemap()
    for f in ("robots.txt", "sitemap.xml", "llms.txt"):
        if not (SITE / f).exists():
            errs.append(f"{f} missing")

    print("=" * 74)
    print(f"SITE CHECK — {len(pages)} page(s)")
    print("=" * 74)
    if not errs:
        print("PASS")
        return 0
    for e in errs:
        print(f"  [FAIL] {e}")
    print("-" * 74)
    print(f"FAIL — {len(errs)} issue(s)")
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
