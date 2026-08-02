#!/usr/bin/env python3
"""build.py — generate the site's content pages from markdown we already wrote.

The launch content existed for weeks as markdown in `docs/` and `plan/content/`; it
had simply never been built into pages, so `sitemap.xml` advertised 9 URLs that 404'd.
This turns those documents into real pages that satisfy `check_site.py`:
full meta/canonical/OG/Twitter/JSON-LD, no dead links, no render-blocking third party.

Design notes
------------
* **One template, one head.** Every page gets the same SEO head from `_head()`, so a
  missing OG tag is impossible by construction rather than by discipline.
* **`markdown_it` only** (already in the venv) — no new dependency for a static build.
* **Per-page JSON-LD type**: TechArticle for docs/blog, WebPage otherwise. Search and
  answer engines treat a documentation page and a marketing page differently.
* Every generated page is listed in `PAGES`, and `check_site.py` verifies the sitemap
  contains no URL without a file — so the sitemap and the site cannot drift apart.

Usage:  python site/build.py         # write all pages
        python site/build.py --list  # show the page plan
"""
from __future__ import annotations

import html as _html
import re
import sys
from pathlib import Path

from markdown_it import MarkdownIt

ROOT = Path(__file__).resolve().parent.parent
SITE = ROOT / "site"
BASE = "https://lucin.security"

# (output path, source markdown, <title>, meta description, schema type, nav-section)
PAGES: list[tuple[str, str, str, str, str, str]] = [
    ("docs", "docs/quickstart.md",
     "Quickstart — Lucin",
     "Install Lucin and scan your first AI agent in under a minute. No API key, no signup, no telemetry — the scanner runs entirely on your machine.",
     "TechArticle", "Docs"),
    ("benchmarks", "docs/methodology.md",
     "Benchmarks & methodology — Lucin",
     "Exactly how Lucin's precision and recall are measured, on which corpora, and the commands that regenerate every published number. Includes what the numbers do not cover.",
     "TechArticle", "Benchmarks"),
    ("limits", "docs/limits.md",
     "What Lucin misses — Limits",
     "The honest coverage gaps: a 24% false-negative rate, 17% SSRF recall, path traversal deliberately unregistered, and why precision was chosen over recall.",
     "TechArticle", "Limits"),
    ("docs/threat-model", "docs/threat-model.md",
     "Threat model — Lucin",
     "What Lucin defends against, what it explicitly does not, and the trust boundaries assumed for an AI agent's tool graph.",
     "TechArticle", "Docs"),
    # Blog posts (index + 3 articles) are built by build_blog.py, through a
    # bespoke post template — not this generic one.
    ("runtime", "plan/content/runtime_preview.md",
     "Runtime enforcement — design-partner preview",
     "GUARD enforces the same information-flow model the scanner uses statically. It is a design-partner preview, not generally available — this page states plainly what is validated and what is not.",
     "WebPage", "Docs"),
    ("changelog", "plan/content/changelog.md",
     "Changelog — Lucin",
     "Dated record of what changed in Lucin, including the changes that were reverted and why. A changelog that only lists wins is marketing.",
     "Article", "Changelog"),
    ("compare/semgrep", "plan/content/compare_semgrep.md",
     "Lucin vs Semgrep — an honest comparison",
     "Semgrep is a better general-purpose SAST tool; Lucin finds agent-specific information-flow problems Semgrep structurally cannot. Where each wins, with measured numbers.",
     "Article", "Docs"),
    ("compare/codeql", "plan/content/compare_codeql.md",
     "Lucin vs CodeQL — an honest comparison",
     "CodeQL is a far more powerful analysis engine; it does not model an AI agent's tool graph. The three cases it cannot flag, and why our LLM-boundary assumption differs.",
     "Article", "Docs"),
]

# Lean, matches the homepage nav's philosophy: Rules/Benchmarks/Limits/Changelog
# are reachable via the tab strip on any docs-family page (see TAB_FAMILY below),
# not repeated as separate top-nav items on every page.
NAV = [("Blog", "/blog/"), ("Docs", "/docs/")]

# Two-dot-and-rule wordmark, reused verbatim across every page (homepage included) —
# do not redraw. Right dot is the one reserved red accent.
_LOGO_SVG = ('<svg width="18" height="18" viewBox="0 0 20 20" aria-hidden="true">'
             '<circle cx="3.5" cy="10" r="2.6" fill="#141414"></circle>'
             '<line x1="6.1" y1="10" x2="13.9" y2="10" stroke="#141414" stroke-width="1.6"></line>'
             '<circle cx="16.5" cy="10" r="2.6" fill="#D6321F"></circle></svg>')


def _head(title: str, desc: str, url: str, schema: str) -> str:
    """The single source of SEO truth for every generated page."""
    t, d = _html.escape(title), _html.escape(desc)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{t}</title>
<meta name="description" content="{d}">
<link rel="canonical" href="{url}">
<link rel="stylesheet" href="/fonts.css">
<meta name="robots" content="index,follow,max-image-preview:large">
<meta property="og:type" content="article">
<meta property="og:site_name" content="Lucin">
<meta property="og:url" content="{url}">
<meta property="og:title" content="{t}">
<meta property="og:description" content="{d}">
<meta property="og:image" content="{BASE}/og.png">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta property="og:image:alt" content="Lucin — static analysis for AI agents">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="{t}">
<meta name="twitter:description" content="{d}">
<meta name="twitter:image" content="{BASE}/og.png">
<script type="application/ld+json">
{{"@context":"https://schema.org","@type":"{schema}",
 "headline":"{t}","description":"{d}","url":"{url}",
 "isPartOf":{{"@type":"WebSite","name":"Lucin","url":"{BASE}/"}},
 "publisher":{{"@type":"Organization","name":"Lucin Labs","url":"{BASE}/"}}}}
</script>
{_CSS}
</head>"""


# Paper/ink/red "instrument panel" brand (2026-08 redesign) — one saturated
# colour on the whole site, reserved for danger/critical and the brand accent.
# Squared-off radii (2-6px) and 1px hairline / 1.5-2px emphasis borders read as
# instrument, not the 80-124px pill radii competitors use.
_CSS = """<style>
:root{
  --canvas:#FAFAF8; --surface:#F3F2EE; --surface-muted:#F1F0EC; --sunken:#141414;
  --ink:#141414; --ink-soft:#3D4147; --ink-muted:#6C7076;
  --line:#D7D9DC; --line-strong:#141414;
  --sev-crit:#D6321F; --sev-high:#B85C1F; --sev-med:#B8860B; --sev-low:#6C7076;
  --ff:'IBM Plex Sans',-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
  --ff-heading:'Space Grotesk',sans-serif;
  --mono:'IBM Plex Mono',ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,monospace;
  --radius:4px; --radius-chip:3px;
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--canvas);color:var(--ink);font-family:var(--ff);
  font-size:16px;line-height:1.65;-webkit-font-smoothing:antialiased}
a{color:inherit}
::selection{background:var(--ink);color:var(--canvas)}
:focus-visible{outline:2px solid var(--ink);outline-offset:2px;border-radius:4px}
nav{position:sticky;top:0;z-index:50;backdrop-filter:blur(10px);
  background:rgba(250,250,248,.92);border-bottom:2px solid var(--ink)}
.nav-in{max-width:1120px;margin:0 auto;padding:0 24px;display:flex;align-items:center;
  gap:26px;height:58px;font-size:14px}
.nav-in .mark{display:inline-flex;align-items:center;gap:9px;font-family:var(--ff-heading);
  font-weight:700;font-size:16px;letter-spacing:-.01em}
.nav-in a{color:var(--ink-soft);text-decoration:none;font-weight:500}
.nav-in a:hover{color:var(--sev-crit)}
.nav-in .right{margin-left:auto;display:flex;gap:16px;align-items:center}
.install{font-family:var(--mono);font-size:13px;background:var(--sunken);
  border:1px solid var(--sunken);border-radius:var(--radius);padding:7px 12px;
  color:#C7CAD1}
main{max-width:760px;margin:0 auto;padding:56px 24px 96px}
h1{font-family:var(--ff-heading);font-size:clamp(30px,4.5vw,42px);line-height:1.12;
  letter-spacing:-.025em;font-weight:700;margin:0 0 20px}
h2{font-family:var(--ff-heading);font-size:24px;line-height:1.25;letter-spacing:-.02em;
  font-weight:700;margin:44px 0 14px;padding-top:18px;border-top:1px solid var(--line)}
h3{font-family:var(--ff-heading);font-size:18px;font-weight:600;margin:28px 0 10px}
p,ul,ol,blockquote,table{margin:0 0 16px}
ul,ol{padding-left:22px}
li{margin:5px 0}
strong{color:var(--ink);font-weight:600}
p,li{color:var(--ink-soft)}
a[href]{color:var(--ink);text-decoration:underline;text-decoration-color:var(--line);
  text-underline-offset:3px}
a[href]:hover{text-decoration-color:var(--sev-crit);color:var(--sev-crit)}
blockquote{border-left:3px solid var(--sev-crit);padding:2px 0 2px 16px;
  color:var(--ink-muted)}
/* code: inline is a light chip with a border; blocks are the one deliberate dark
   inversion (matches the report/hero convention) — pre code resets the chip so
   nested code is not double-boxed. */
code{font-family:var(--mono);font-size:.86em;background:var(--surface-muted);
  border:1px solid var(--line);border-radius:var(--radius-chip);padding:.1em .35em;
  font-variant-ligatures:none}
pre{font-family:var(--mono);font-size:13px;line-height:1.6;background:var(--sunken);
  color:#C7CAD1;border-radius:var(--radius);padding:14px 16px;
  margin:0 0 18px;overflow:auto;-webkit-font-smoothing:auto}
pre code{background:0 0;border:0;padding:0;font-size:1em;color:inherit}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{border:1px solid var(--line);padding:8px 10px;text-align:left;vertical-align:top}
th{background:var(--surface);color:var(--ink);font-weight:600}
hr{border:0;border-top:1px solid var(--line);margin:32px 0}
footer{border-top:1px solid var(--line);margin-top:64px;padding:28px 24px 56px;
  color:var(--ink-muted);font-size:13px}
footer .in{max-width:760px;margin:0 auto;display:flex;align-items:center;gap:18px;flex-wrap:wrap}
footer .mark-sm{font-family:var(--ff-heading);font-weight:700;color:var(--ink)}
footer a{text-decoration:none;color:var(--ink-muted)}
footer a:hover{color:var(--sev-crit)}

@media(max-width:640px){.nav-in .links,.install{display:none}main{padding-top:36px}}

/* ---- docs/benchmarks/limits/rules/changelog "tab family" header ----
   Each is its own real page/route (not a client-side view switch) — the tabs
   are plain links, and the current page's tab gets the active fill. */
.back-home{font-family:var(--mono);font-size:12px;color:var(--ink-muted);text-decoration:none}
.back-home:hover{color:var(--sev-crit)}
.eyebrow2{font-family:var(--mono);font-size:12px;letter-spacing:.14em;color:var(--sev-crit);
  font-weight:600;margin-top:30px}
h1.page-h1{font-family:var(--ff-heading);font-weight:700;font-size:clamp(34px,3.8vw,46px);
  letter-spacing:-.025em;line-height:1.06;margin:16px 0 0}
p.page-dek{max-width:62ch;margin-top:18px;font-size:17.5px;line-height:1.6;color:var(--ink-soft)}
.tab-row{display:flex;gap:0;margin-top:34px;border:1.5px solid var(--ink);border-radius:2px;
  width:fit-content;overflow:hidden}
.tab-pill{padding:10px 18px;font-family:var(--mono);font-size:12.5px;text-decoration:none;
  color:var(--ink);border-right:1px solid var(--ink);transition:background .18s,color .18s}
.tab-pill:last-child{border-right:0}
.tab-pill:hover{background:var(--surface);color:var(--ink)}
.tab-pill.active{background:var(--ink);color:var(--canvas)}
.tab-pill.active:hover{background:var(--ink);color:var(--canvas)}
</style>"""


def _chrome(active: str) -> str:
    links = "".join(
        f'<a href="{href}"{" aria-current=\"page\"" if label == active else ""}>{label}</a>'
        for label, href in NAV)
    return f"""<body>
<nav><div class="nav-in">
  <a class="mark" href="/" aria-label="Lucin home">{_LOGO_SVG}LUCIN</a>
  <span class="links" style="display:flex;gap:22px">{links}</span>
  <span class="right">
    <span class="install">$ pip install lucin</span>
  </span>
</div></nav>
<main>"""


def _footer() -> str:
    return f"""</main>
<footer><div class="in">
  <span class="mark-sm">LUCIN</span>
  <span>Every claim reproducible from a committed command.</span>
  <span style="display:flex;gap:14px;margin-left:auto">
    <a href="/benchmarks/">Methodology</a>
    <a href="/limits/">What it misses</a>
    <a href="/docs/threat-model/">Threat model</a>
  </span>
</div></footer>
</body>
</html>"""


def _demote_headings(md_html: str) -> str:
    """The markdown files each open with their own H1; the template supplies the page
    H1, so shift the document down a level to keep exactly one H1 per page (an
    accessibility and SEO requirement)."""
    for src, dst in ((5, 6), (4, 5), (3, 4), (2, 3), (1, 2)):
        md_html = md_html.replace(f"<h{src}>", f"<h{dst}>").replace(f"</h{src}>", f"</h{dst}>")
    return md_html


# The docs/benchmarks/limits/rules/changelog "hub" pages share one tab strip.
# Each tab is a real page/route — this is a shared nav affordance, not a
# client-side view switch — so the "active" tab is just a styled, non-linked
# current page, and the rest are plain links to their own real URLs.
TAB_FAMILY: list[tuple[str, str, str]] = [
    ("docs", "docs", "/docs/"),
    ("benchmarks", "benchmarks", "/benchmarks/"),
    ("limits", "limits", "/limits/"),
    ("rules", "rules", "/rules/"),
    ("changelog", "changelog", "/changelog/"),
]
_TAB_KICKERS = {"docs": "DOCUMENTATION", "benchmarks": "BENCHMARKS", "limits": "LIMITS",
                "rules": "RULES", "changelog": "CHANGELOG"}


def tab_header(active: str, title: str, dek: str) -> str:
    """The shared header for a tab-family page: back-link, eyebrow, H1, dek, tab strip."""
    tabs = "".join(
        f'<span class="tab-pill active">{label}</span>' if tid == active
        else f'<a href="{href}" class="tab-pill">{label}</a>'
        for tid, label, href in TAB_FAMILY
    )
    return f"""<a class="back-home" href="/">← Home</a>
<div class="eyebrow2">{_TAB_KICKERS.get(active, "")}</div>
<h1 class="page-h1">{_html.escape(title)}</h1>
<p class="page-dek">{_html.escape(dek)}</p>
<div class="tab-row">{tabs}</div>"""


# Secondary pages that hang off Documentation but aren't one of the 5 primary
# hub destinations (threat-model, the GUARD preview, the compare pages) get the
# same visual weight as a tab-family header — eyebrow, big H1, dek — but a
# "← back" link instead of the 5-pill strip, since they're one level deeper.
_SUB_PAGES = {
    "docs/threat-model": ("THREAT MODEL", "/docs/", "← Docs"),
    "runtime": ("RUNTIME (GUARD)", "/docs/", "← Docs"),
    "compare/semgrep": ("COMPARE", "/compare/", "← Compare"),
    "compare/codeql": ("COMPARE", "/compare/", "← Compare"),
}


def sub_header(kicker: str, title: str, dek: str, back_href: str, back_label: str) -> str:
    return f"""<a class="back-home" href="{back_href}">{back_label}</a>
<div class="eyebrow2">{_html.escape(kicker)}</div>
<h1 class="page-h1">{_html.escape(title)}</h1>
<p class="page-dek">{_html.escape(dek)}</p>"""


def build_page(out: str, src: str, title: str, desc: str, schema: str, active: str) -> Path:
    md_path = ROOT / src
    text = md_path.read_text()
    # Drop a leading H1 — the template renders the page title instead.
    text = re.sub(r"\A\s*#\s+.*?\n", "", text, count=1)
    body = _demote_headings(MarkdownIt("commonmark", {"html": False}).enable("table").render(text))
    url = f"{BASE}/{out}/"
    page_title = title.split(" — ")[0]
    tab_id = out if out in {t[0] for t in TAB_FAMILY} else None
    if tab_id:
        header = tab_header(tab_id, page_title, desc)
    elif out in _SUB_PAGES:
        kicker, back_href, back_label = _SUB_PAGES[out]
        header = sub_header(kicker, page_title, desc, back_href, back_label)
    else:
        header = f"<h1>{_html.escape(page_title)}</h1>\n"
    page = _head(title, desc, url, schema) + _chrome(active) + header + body + _footer()
    dest = SITE / out / "index.html"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(page)
    return dest


# The two comparison pages didn't have a landing spot of their own — a reader had to
# already know the exact URL. This is the same "index above the leaves" pattern as
# /rules/ and /blog/: one real page, two rows, both real links.
_COMPARE_ROWS = [
    ("semgrep", "vs. Semgrep", "A better general-purpose SAST tool; Lucin finds agent-specific information-flow problems Semgrep structurally cannot."),
    ("codeql", "vs. CodeQL", "A far more powerful analysis engine; it does not model an AI agent's tool graph. The three cases it cannot flag, and why."),
]


def build_compare_index() -> Path:
    title = "How Lucin compares — Lucin"
    desc = "Honest, measured comparisons against general-purpose static analysis tools: where each wins, with numbers, not marketing."
    url = f"{BASE}/compare/"
    rows = "".join(
        f'<a href="/compare/{slug}/" style="display:flex;gap:16px;align-items:baseline;'
        f'padding:16px 2px;border-bottom:1px solid var(--line);text-decoration:none;color:var(--ink)">'
        f'<span style="font-family:var(--ff-heading);font-weight:700;min-width:160px">{_html.escape(label)}</span>'
        f'<span style="color:var(--ink-soft);font-size:14.5px">{_html.escape(dek)}</span></a>'
        for slug, label, dek in _COMPARE_ROWS
    )
    body = (sub_header("COMPARE", "How Lucin compares", desc, "/docs/", "← Docs")
            + f'<div style="margin-top:24px;border-top:2px solid var(--ink)">{rows}</div>')
    page = _head(title, desc, url, "WebPage") + _chrome("Docs") + body + _footer()
    dest = SITE / "compare" / "index.html"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(page)
    return dest


def main(argv: list[str]) -> int:
    if "--list" in argv:
        for out, src, title, *_ in PAGES:
            print(f"  /{out}/  <-  {src}   ({title})")
        print("  /compare/  <- index")
        return 0
    for out, src, title, desc, schema, active in PAGES:
        if not (ROOT / src).exists():
            print(f"  [SKIP] {src} missing")
            continue
        dest = build_page(out, src, title, desc, schema, active)
        print(f"  [ok] /{out}/ <- {src}  ({dest.stat().st_size // 1024} KB)")
    dest = build_compare_index()
    print(f"  [ok] /compare/  ({dest.stat().st_size // 1024} KB)")
    print(f"\n{len(PAGES) + 1} page(s) built into {SITE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
