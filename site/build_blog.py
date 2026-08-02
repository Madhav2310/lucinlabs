#!/usr/bin/env python3
"""build_blog.py — blog index + bespoke post template, real content.

WHY A SEPARATE BUILDER
-----------------------
The three posts in `plan/content/` are full, richly-sourced articles (code
samples, a comparison table, citations) — not the shorter draft blocks in the
design handoff's prototype. This renders the REAL markdown through the new
paper/ink/red typed-block system (heading / paragraph / code / table /
citation), instead of replacing real content with the shorter design-file
draft text. The one-line "dek" under each title IS taken verbatim from the
design file — that's exactly what an editorial one-liner teaser is for.

Each post's markdown carries its own front-matter line (e.g. "*~1,250 words.
... Product name placeholder `lucin` pending rename.*") — internal editorial
scaffolding written before launch, not something a reader should see on a
published page. It is detected structurally (an all-italic paragraph
immediately followed by a divider, right after the title) and dropped, along
with all `---` divider rules (spacing carries that job in the new design).
A trailing all-italic "Sources: ..." paragraph is kept, but rendered as a
distinct citation line, not a body paragraph.

Usage:  python site/build_blog.py         # write /blog/ index + 3 posts
        python site/build_blog.py --list  # show the post plan
"""
from __future__ import annotations

import html as _html
import re
import sys
from pathlib import Path

from markdown_it import MarkdownIt

ROOT = Path(__file__).resolve().parent.parent
SITE = ROOT / "site"
BASE = "https://lucin.pages.dev"

sys.path.insert(0, str(Path(__file__).resolve().parent))
from build import _CSS, _LOGO_SVG, NAV  # noqa: E402  (reuse the one template's tokens)

# (slug, source markdown, kicker, date, read-time, dek, date_modified — dek is the
#  design file's approved one-line teaser, kept verbatim as both the on-page dek and
#  meta description. date_modified is None unless the post was substantively
#  corrected after publication — see dateModified in the JSON-LD.)
POSTS: list[tuple[str, str, str, str, str, str, str | None]] = [
    ("hugging-face-agent-breach", "plan/content/hf_teardown.md", "TEARDOWN", "29 JUL 2026", "12 min read",
     "A malicious dataset, a tool that executes code, a credential read, an outbound call. We rebuilt the incident as an information-flow graph — and found the single edge that carries all 17,600 actions.",
     "03 AUG 2026"),  # corrected: action count, timeframe, attacker description, detection framing
    ("lethal-trifecta", "plan/content/blog_lethal_trifecta.md", "METHOD", "29 JUL 2026", "9 min read",
     "Private data, untrusted content, external reach. Any one is fine; all three wired together is the incident. Here is how to read those edges off your own tool list — and which to cut versus gate.",
     None),
    ("reproducible-benchmark", "plan/content/blog_reproducible_benchmark.md", "PROOF", "29 JUL 2026", "7 min read",
     "A security tool that will not show you its benchmark harness is asking you to take its word for it. Here is ours, and the exact command that regenerates every number on this site.",
     None),
]


def _iso_date(d: str) -> str:
    """'29 JUL 2026' -> '2026-07-29'."""
    import datetime
    return datetime.datetime.strptime(d, "%d %b %Y").strftime("%Y-%m-%d")

_md = MarkdownIt("commonmark", {"html": False}).enable("table")

# markdown-it *_open/*_close token-type pairs that form one logical top-level
# block. Walking the token stream directly (rather than re-parsing the
# rendered HTML string with a hand-rolled offset scanner) reuses the
# library's own renderer for each slice, so inline formatting/links/escaping
# is exactly what markdown-it would have produced — no custom string slicing
# to get subtly wrong on real content.
_OPEN_CLOSE = {
    "heading_open": ("heading_close", None),  # tag comes from the token itself
    "paragraph_open": ("paragraph_close", "p"),
    "bullet_list_open": ("bullet_list_close", "ul"),
    "ordered_list_open": ("ordered_list_close", "ol"),
    "table_open": ("table_close", "table"),
    "blockquote_open": ("blockquote_close", "blockquote"),
}
_ATOMIC = {"fence": "pre", "code_block": "pre", "hr": "hr"}


def _split_blocks(text: str) -> list[tuple[str, str]]:
    tokens = _md.parse(text)
    blocks: list[tuple[str, str]] = []
    i, n = 0, len(tokens)
    while i < n:
        t = tokens[i]
        if t.level != 0:
            i += 1
            continue
        if t.type in _OPEN_CLOSE:
            close_type, tag = _OPEN_CLOSE[t.type]
            tag = tag or t.tag
            j = i + 1
            while not (tokens[j].type == close_type and tokens[j].level == 0):
                j += 1
            group = tokens[i:j + 1]
            blocks.append((tag, _md.renderer.render(group, _md.options, {})))
            i = j + 1
        elif t.type in _ATOMIC:
            blocks.append((_ATOMIC[t.type], _md.renderer.render([t], _md.options, {})))
            i += 1
        else:
            i += 1
    return blocks


def _is_all_italic_paragraph(tag: str, outer: str) -> bool:
    if tag != "p":
        return False
    inner = re.sub(r"^<p>|</p>$", "", outer.strip())
    return bool(re.fullmatch(r"<em>.*</em>", inner, re.S))


def _render_blocks(blocks: list[tuple[str, str]]) -> str:
    out = []
    # Drop a leading italic front-matter line (immediately followed by <hr>),
    # and all <hr> dividers throughout — spacing carries that job now.
    i = 0
    if len(blocks) >= 2 and _is_all_italic_paragraph(*blocks[0]) and blocks[1][0] == "hr":
        i = 2
    # A trailing italic "Sources: ..." paragraph (possibly preceded by a bare <hr>)
    # renders as a citation line, not a body paragraph.
    sources_html = ""
    j = len(blocks)
    if j > i and _is_all_italic_paragraph(*blocks[j - 1]):
        inner = re.sub(r"^<p><em>|</em></p>$", "", blocks[j - 1][1].strip())
        sources_html = f'<p class="post-sources">{inner}</p>'
        j -= 1
        if j > i and blocks[j - 1][0] == "hr":
            j -= 1

    for tag, outer in blocks[i:j]:
        if tag == "hr":
            continue
        if tag in ("h2", "h3"):
            inner = re.sub(rf"^<{tag}>|</{tag}>$", "", outer.strip())
            out.append(f'<{tag} class="post-h">{inner}</{tag}>')
        elif tag == "p":
            inner = re.sub(r"^<p>|</p>$", "", outer.strip())
            out.append(f'<p class="post-p">{inner}</p>')
        elif tag in ("ul", "ol"):
            out.append(outer.replace(f"<{tag}>", f'<{tag} class="post-list">', 1))
        elif tag == "pre":
            out.append(outer.replace("<pre>", '<pre class="post-code">', 1))
        elif tag == "table":
            out.append(f'<div class="post-table-wrap">{outer}</div>')
    if sources_html:
        out.append(sources_html)
    return "\n".join(out)


def _read_post(src: str) -> tuple[str, str]:
    """Returns (title, rendered_body_html)."""
    text = (ROOT / src).read_text()
    m = re.match(r"\A\s*#\s+(.*?)\n", text)
    title = m.group(1).strip() if m else src
    text = re.sub(r"\A\s*#\s+.*?\n", "", text, count=1)
    blocks = _split_blocks(text)
    return title, _render_blocks(blocks)


_POST_CSS = """<style>
.post-meta-row{display:flex;gap:16px;margin-top:32px;font-family:var(--mono);font-size:11.5px;color:var(--ink-muted)}
.post-meta-row .kicker{color:var(--sev-crit);font-weight:600}
.post-h1{font-family:var(--ff-heading);font-weight:700;font-size:clamp(32px,3.6vw,44px);
  letter-spacing:-.025em;line-height:1.1;margin:16px 0 0}
.post-dek{margin-top:20px;font-size:19px;line-height:1.55;color:var(--ink-soft)}
.post-rule{height:2px;background:var(--ink);margin:36px 0 0}
.post-body{margin-top:32px;font-size:17px;line-height:1.7;color:#242628}
.post-body>*{margin-bottom:22px}
h2.post-h{font-family:var(--ff-heading);font-weight:700;font-size:22px;letter-spacing:-.015em;margin:38px 0 -6px}
h3.post-h{font-family:var(--ff-heading);font-weight:700;font-size:18px;letter-spacing:-.01em;margin:30px 0 -6px}
p.post-p{margin:0}
p.post-p code{font-family:var(--mono);font-size:.88em;background:var(--surface-muted);
  border:1px solid var(--line);border-radius:var(--radius-chip);padding:.1em .35em}
p.post-p a{color:var(--ink);text-decoration:underline;text-decoration-color:var(--line);text-underline-offset:2px}
p.post-p a:hover{text-decoration-color:var(--sev-crit);color:var(--sev-crit)}
ul.post-list,ol.post-list{padding-left:22px;color:#242628}
ul.post-list li,ol.post-list li{margin:8px 0}
ul.post-list code,ol.post-list code{font-family:var(--mono);font-size:.88em;background:var(--surface-muted);
  border:1px solid var(--line);border-radius:var(--radius-chip);padding:.1em .35em}
pre.post-code{margin:0;background:var(--sunken);color:#C7CAD1;padding:18px 20px;border-radius:6px;
  font-family:var(--mono);font-size:13px;line-height:1.7;overflow-x:auto}
pre.post-code code{background:0 0;border:0;padding:0;color:inherit}
.post-table-wrap{overflow-x:auto}
.post-table-wrap table{width:100%;border-collapse:collapse;font-size:14.5px}
.post-table-wrap th,.post-table-wrap td{border:1px solid var(--line);padding:9px 12px;text-align:left;vertical-align:top}
.post-table-wrap th{background:var(--surface);font-weight:600;font-family:var(--ff-heading)}
p.post-sources{margin:0;padding:16px 20px;background:var(--surface-muted);border-left:3px solid var(--sev-crit);
  font-size:13.5px;line-height:1.6;color:var(--ink-muted)}
p.post-sources em{font-style:normal}
.post-cta{margin:44px 0 96px;background:var(--sunken);color:#FAFAF8;border-radius:6px;padding:36px 40px;
  display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:20px}
.post-cta .t{font-family:var(--ff-heading);font-weight:700;font-size:20px}
.post-cta .s{color:#B7BAC0;font-size:13.5px;margin-top:6px}
.post-cta .pill{display:inline-flex;align-items:center;gap:14px;height:48px;padding:0 6px 0 20px;
  background:#08090A;border:1px solid #2B2B2B;border-radius:2px;font-family:var(--mono);font-size:13.5px;
  white-space:nowrap;color:#fff}
.post-cta .pill .prompt{color:#F0917F}
.back-link{font-family:var(--mono);font-size:12px;color:var(--ink-muted);text-decoration:none}
.back-link:hover{color:var(--sev-crit)}
</style>"""


def _head(title: str, desc: str, url: str, date_published: str = "", date_modified: str = "") -> str:
    t, d = _html.escape(title), _html.escape(desc)
    dates_ld = ""
    if date_published:
        dates_ld += f',\n "datePublished":"{date_published}"'
    if date_modified:
        dates_ld += f',\n "dateModified":"{date_modified}"'
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{t} — Lucin</title>
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
{{"@context":"https://schema.org","@type":"TechArticle",
 "headline":"{t}","description":"{d}","url":"{url}"{dates_ld},
 "isPartOf":{{"@type":"WebSite","name":"Lucin","url":"{BASE}/"}},
 "publisher":{{"@type":"Organization","name":"Lucin Labs","url":"{BASE}/"}}}}
</script>
{_CSS}
{_POST_CSS}
</head>"""


def _nav() -> str:
    links = "".join(f'<a href="{href}">{label}</a>' for label, href in NAV)
    return f"""<body>
<nav><div class="nav-in">
  <a class="mark" href="/" aria-label="Lucin home">{_LOGO_SVG}LUCIN</a>
  <span class="links" style="display:flex;gap:22px">{links}</span>
  <span class="right"><span class="install">$ pip install lucin</span></span>
</div></nav>"""


def _cta_card() -> str:
    return """<div class="post-cta">
  <div><div class="t">Check your own agent for this shape.</div><div class="s">Free, MIT, 30 seconds.</div></div>
  <div class="pill"><span><span class="prompt">$</span> pip install lucin</span></div>
</div>"""


def build_post(slug: str, src: str, kicker: str, date: str, read: str, dek: str,
                date_modified: str | None = None) -> Path:
    title, body_html = _read_post(src)
    url = f"{BASE}/blog/{slug}/"
    meta_dates = f"<span>{_html.escape(date)}</span>"
    if date_modified:
        meta_dates += f'<span title="Corrected">updated {_html.escape(date_modified)}</span>'
    page = (
        _head(title, dek, url, _iso_date(date), _iso_date(date_modified) if date_modified else "") + _nav()
        + f"""<article style="max-width:760px;margin:0 auto;padding:40px 24px 0">
  <a class="back-link" href="/blog/">← All field notes</a>
  <div class="post-meta-row"><span class="kicker">{_html.escape(kicker)}</span>{meta_dates}<span>{_html.escape(read)}</span></div>
  <h1 class="post-h1">{_html.escape(title)}</h1>
  <p class="post-dek">{_html.escape(dek)}</p>
  <div class="post-rule"></div>
  <div class="post-body">
{body_html}
  </div>
  {_cta_card()}
</article>
</body>
</html>"""
    )
    dest = SITE / "blog" / slug / "index.html"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(page)
    return dest


def build_index() -> Path:
    url = f"{BASE}/blog/"
    rows = ""
    for slug, _src, kicker, date, read, dek, _dm in POSTS:
        title, _ = _read_post(_posts_src(slug))
        rows += f"""<a href="/blog/{slug}/" class="blog-row">
  <div class="blog-row-meta"><div class="k">{_html.escape(kicker)}</div><div>{_html.escape(date)}</div><div>{_html.escape(read)}</div></div>
  <div>
    <div class="blog-row-title">{_html.escape(title)}</div>
    <p class="blog-row-dek">{_html.escape(dek)}</p>
    <div class="blog-row-cta">Read {"the teardown" if kicker == "TEARDOWN" else "the explainer" if kicker == "METHOD" else "the write-up"} →</div>
  </div>
</a>"""
    page = (
        _head("Field notes on agent security", "Teardowns of real incidents, the graph theory behind the detectors, and the benchmark numbers with the commands that produce them.", url)
        + """<style>
.blog-hero{max-width:1000px;margin:0 auto;padding:56px 24px 0}
.blog-hero h1{font-family:var(--ff-heading);font-weight:700;font-size:clamp(36px,4vw,52px);
  letter-spacing:-.025em;line-height:1.05;margin:18px 0 0}
.blog-hero p{max-width:60ch;margin-top:18px;font-size:17px;line-height:1.6;color:var(--ink-soft)}
.blog-list{max-width:1000px;margin:0 auto;padding:40px 24px 0;border-top:2px solid var(--ink)}
.blog-row{display:grid;grid-template-columns:150px 1fr;gap:28px;padding:32px 0;border-bottom:1px solid var(--line);
  text-decoration:none;color:var(--ink);transition:padding-left .3s var(--ease,ease),background .2s}
.blog-row:hover{padding-left:12px;background:var(--surface)}
.blog-row-meta{font-family:var(--mono);font-size:11.5px;color:var(--ink-muted);line-height:1.8}
.blog-row-meta .k{color:var(--sev-crit);font-weight:600}
.blog-row-title{font-family:var(--ff-heading);font-weight:700;font-size:25px;letter-spacing:-.02em;line-height:1.2}
.blog-row-dek{margin-top:12px;font-size:15px;line-height:1.6;color:var(--ink-soft);max-width:64ch}
.blog-row-cta{margin-top:14px;font-size:13.5px;font-weight:600;color:var(--sev-crit)}
.blog-foot-note{max-width:1000px;margin:28px auto 0;padding:0 24px;font-size:13.5px;color:var(--ink-muted)}
</style>"""
        + _nav()
        + f"""<div class="blog-hero">
  <div class="eyebrow" style="font-family:var(--mono);font-size:12px;letter-spacing:.14em;color:var(--sev-crit);font-weight:600">THE LUCIN BLOG</div>
  <h1>Field notes on agent security.</h1>
  <p>Teardowns of real incidents, the graph theory behind the detectors, and the benchmark numbers with the commands that produce them.</p>
</div>
<div class="blog-list">
{rows}
</div>
<p class="blog-foot-note">More posts as we publish them. Every claim links to the command that reproduces it.</p>
<div style="max-width:1000px;margin:44px auto 0;padding:0 24px 96px">{_cta_card()}</div>
</body>
</html>"""
    )
    dest = SITE / "blog" / "index.html"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(page)
    return dest


def _posts_src(slug: str) -> str:
    return next(src for s, src, *_ in POSTS if s == slug)


def main(argv: list[str]) -> int:
    if "--list" in argv:
        for slug, src, *_ in POSTS:
            print(f"  /blog/{slug}/  <-  {src}")
        print("  /blog/  <- index")
        return 0
    for slug, src, kicker, date, read, dek, date_modified in POSTS:
        dest = build_post(slug, src, kicker, date, read, dek, date_modified)
        print(f"  [ok] /blog/{slug}/  ({dest.stat().st_size // 1024} KB)")
    dest = build_index()
    print(f"  [ok] /blog/  ({dest.stat().st_size // 1024} KB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
