#!/usr/bin/env python3
"""build_rules.py — one page per detection rule, generated from the shipping code.

WHY
---
This is the Snyk-vuln-DB / Socket-package-page pattern: a programmatic hub built from
data the product already owns. Each page is definition + why it matters + real-world
incident + how to fix + the command to detect it — which is exactly the
"extractable evidence richness" (definitions, concrete facts, procedural steps) that
the AI-citation studies found predictive, and it is question-shaped content, which is
what actually triggers AI answers (Pew: 8% of 1-2 word queries produce an AI summary
vs 53% of 10+ word queries).

Source of truth is `src/lucin/rule_docs.py` — the same catalog `lucin explain` uses —
so a page can never describe a rule differently from the CLI.

HONESTY RULE (enforced below)
-----------------------------
A page is generated ONLY for a rule with real content: a description AND a fix. Rules
that exist in the detector registry but have no written copy are NOT given a thin
placeholder page — they are listed in the build output as work to do. Thin
programmatic pages are the failure mode of this pattern and we are not doing it.

Usage:  python site/build_rules.py         # write /rules/ index + per-rule pages
        python site/build_rules.py --list  # show coverage, write nothing
"""
from __future__ import annotations

import html as _html
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
SITE = ROOT / "site"
BASE = "https://lucin.pages.dev"

import lucin.rule_docs as rd  # noqa: E402
from build import _CSS, _chrome, _footer, tab_header  # reuse the one template  # noqa: E402


def _merged() -> dict[str, dict]:
    """Merge the catalog with the deeper `lucin explain` docs. Explain wins on overlap
    because it carries the incident references and the remediation detail."""
    out: dict[str, dict] = {}
    for rid, e in rd.RULE_CATALOG.items():
        out[rid] = {
            "title": e.get("title", rid),
            "severity": str(e.get("severity", "")).upper(),
            "what": e.get("description", ""),
            "why": e.get("real_world", ""),
            "fix": e.get("fix_summary", ""),
            "asi": list(e.get("owasp_asi", []) or []),
        }
    for rid, e in rd._EXPLAIN_DOCS.items():
        cur = out.setdefault(rid, {"title": rid, "severity": "", "what": "", "why": "",
                                   "fix": "", "asi": []})
        cur["title"] = e.get("title", cur["title"])
        cur["severity"] = str(e.get("severity", cur["severity"])).upper()
        cur["what"] = e.get("what_it_means") or cur["what"]
        cur["why"] = e.get("why_it_matters") or cur["why"]
        cur["fix"] = e.get("how_to_fix") or cur["fix"]
        if e.get("owasp_ref"):
            cur["asi"] = cur["asi"] or [e["owasp_ref"]]
    # Rules that exist ONLY as an OWASP mapping must still appear here, with empty
    # copy, so `_publishable` reports them as work to do. Omitting them made the
    # coverage gap invisible — which defeats the point of refusing to ship thin pages.
    for rid, asi in rd._RULE_TO_ASI.items():
        cur = out.setdefault(rid, {"title": rid, "severity": "", "what": "", "why": "",
                                   "fix": "", "asi": []})
        if not cur["asi"]:
            cur["asi"] = list(asi) if isinstance(asi, (list, tuple)) else [str(asi)]
    return out


def _publishable(m: dict[str, dict]) -> tuple[list[str], list[str]]:
    ok = [r for r, v in m.items() if v["what"].strip() and v["fix"].strip()]
    return sorted(ok), sorted(set(m) - set(ok))


def _para(text: str) -> str:
    """Render plain text with newlines/bullets into HTML paragraphs and lists."""
    blocks, buf = [], []
    for line in (text or "").split("\n"):
        s = line.strip()
        if s.startswith(("•", "-", "*")) or (len(s) > 2 and s[0].isdigit() and s[1] in ".)"):
            buf.append(_html.escape(s.lstrip("•-*0123456789.) ").strip()))
        elif s:
            if buf:
                blocks.append("<ul>" + "".join(f"<li>{b}</li>" for b in buf) + "</ul>"); buf = []
            blocks.append(f"<p>{_html.escape(s)}</p>")
    if buf:
        blocks.append("<ul>" + "".join(f"<li>{b}</li>" for b in buf) + "</ul>")
    return "\n".join(blocks)


def _head(title: str, desc: str, url: str, rid: str) -> str:
    t, d = _html.escape(title), _html.escape(desc)
    # Article (NOT TechArticle): Google's Article doc supports only Article,
    # NewsArticle and BlogPosting — TechArticle is valid vocabulary that earns no
    # feature. BreadcrumbList still renders and was the most common type on
    # AI-cited pages. No aggregateRating anywhere: we have no legitimate
    # third-party ratings and will not invent one to unlock a rich snippet.
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
<meta property="og:image:alt" content="Lucin detection rule {_html.escape(rid)}">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="{t}">
<meta name="twitter:description" content="{d}">
<meta name="twitter:image" content="{BASE}/og.png">
<script type="application/ld+json">
{{"@context":"https://schema.org","@graph":[
 {{"@type":"Article","headline":"{t}","description":"{d}","url":"{url}",
   "isPartOf":{{"@type":"WebSite","name":"Lucin","url":"{BASE}/"}},
   "publisher":{{"@type":"Organization","name":"Lucin Labs","url":"{BASE}/",
     "sameAs":["https://github.com/Madhav2310/lucinlabs","https://pypi.org/project/lucin/"]}}}},
 {{"@type":"BreadcrumbList","itemListElement":[
   {{"@type":"ListItem","position":1,"name":"Home","item":"{BASE}/"}},
   {{"@type":"ListItem","position":2,"name":"Rules","item":"{BASE}/rules/"}},
   {{"@type":"ListItem","position":3,"name":"{_html.escape(rid)}","item":"{url}"}}]}}
]}}
</script>
{_CSS}
<style>
.rule-meta{{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin:0 0 22px}}
.chip{{font-family:var(--mono);font-size:11.5px;letter-spacing:.04em;text-transform:uppercase;
  border:1px solid var(--line-strong);border-radius:var(--radius-chip);padding:3px 8px;
  color:var(--ink-soft)}}
.chip.crit{{border-color:var(--sev-crit);color:var(--sev-crit)}}
.chip.high{{border-color:var(--sev-high);color:var(--sev-high)}}
.chip.med{{border-color:var(--sev-med);color:var(--sev-med)}}
.rule-grid{{display:grid;grid-template-columns:1fr;gap:0;margin-top:24px;border-top:2px solid var(--ink)}}
.rule-grid a{{display:flex;gap:12px;align-items:baseline;padding:13px 2px;
  border-bottom:1px solid var(--line);text-decoration:none}}
.rule-grid a:hover{{background:var(--surface)}}
.rule-grid .id{{font-family:var(--mono);font-size:12.5px;color:var(--ink-muted);min-width:132px}}
.rule-grid .t{{color:var(--ink);font-weight:500}}
.rule-grid .s{{margin-left:auto;font-family:var(--mono);font-size:11px;color:var(--ink-muted)}}
</style>
</head>"""


def _sev_class(s: str) -> str:
    return {"CRITICAL": "crit", "HIGH": "high", "MEDIUM": "med"}.get(s, "")


def build_rule(rid: str, v: dict) -> Path:
    title = f"{rid}: {v['title']}"
    first = (v["what"].strip().split("\n")[0])[:150]
    desc = (f"{rid} — {v['title']}. {first} How Lucin detects it and how to fix it.")[:300]
    url = f"{BASE}/rules/{rid}/"
    asi = " · ".join(_html.escape(a) for a in v["asi"]) or "—"
    body = f"""<h1>{_html.escape(title)}</h1>
<div class="rule-meta">
  <span class="chip {_sev_class(v['severity'])}">{_html.escape(v['severity'] or 'n/a')}</span>
  <span class="chip">{_html.escape(rid)}</span>
  <span class="chip">OWASP {asi}</span>
</div>
<h2>What this rule means</h2>
{_para(v['what'])}
<h2>Why it matters</h2>
{_para(v['why']) or '<p>See the threat model for the general case.</p>'}
<h2>How to fix it</h2>
{_para(v['fix'])}
<h2>Detect it</h2>
<pre><code>pip install lucin
lucin scan .                  # all rules
lucin explain {_html.escape(rid)}          # this rule, in your terminal</code></pre>
<p>Findings carry a <code>file:line</code> and, where the rule supports it, a witness
path showing the flow that triggered it. Precision and recall for the whole rule set,
with the commands that regenerate them, are on the
<a href="/benchmarks/">benchmarks page</a> — and the gaps are on
<a href="/limits/">limits</a>.</p>
<p><a href="/rules/">← All detection rules</a></p>"""
    dest = SITE / "rules" / rid / "index.html"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(_head(title, desc, url, rid) + _chrome("Rules") + body + _footer())
    return dest


def build_index(pub: list[str], m: dict[str, dict]) -> Path:
    rows = "".join(
        f'<a href="/rules/{r}/"><span class="id">{r}</span>'
        f'<span class="t">{_html.escape(m[r]["title"])}</span>'
        f'<span class="s">{_html.escape(m[r]["severity"])}</span></a>'
        for r in pub)
    title = "Detection rules — Lucin"
    desc = (f"Every Lucin detection rule: what it catches in an AI agent, why it "
            f"matters, and how to fix it. {len(pub)} documented rules with severity "
            f"and OWASP Agentic mapping.")
    url = f"{BASE}/rules/"
    body = f"""{tab_header("rules", "Detection rules", desc)}
<p style="margin-top:40px">Each rule below has a stable ID that appears in every output format, so a finding
in CI is the same object as a finding in your terminal. Severity is bounded by
evidence: a finding with no witness and no source line is capped below HIGH, because
a reader cannot verify it.</p>
<div class="rule-grid">{rows}</div>
<h2>Coverage, honestly</h2>
<p>{len(pub)} rules are documented here. The scanner ships more detectors than that;
rules without written guidance are deliberately <em>not</em> given placeholder pages,
because a page that restates its own title helps nobody. What the rule set as a whole
does and does not catch is measured on <a href="/benchmarks/">benchmarks</a> and
<a href="/limits/">limits</a>.</p>
<pre><code>pip install lucin
lucin scan .</code></pre>"""
    dest = SITE / "rules" / "index.html"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(_head(title, desc, url, "Rules") + _chrome("Rules") + body + _footer())
    return dest


def main(argv: list[str]) -> int:
    m = _merged()
    pub, thin = _publishable(m)
    if "--list" in argv:
        print(f"publishable ({len(pub)}): {pub}")
        print(f"needs copy ({len(thin)}): {thin}")
        return 0
    for rid in pub:
        build_rule(rid, m[rid])
        print(f"  [ok] /rules/{rid}/  {m[rid]['title']}")
    build_index(pub, m)
    print(f"  [ok] /rules/  (index of {len(pub)})")
    print(f"\n{len(pub)} rule page(s) + index built.")
    if thin:
        print(f"\nNOT published — no written copy yet ({len(thin)}). Add these to "
              f"RULE_CATALOG / _EXPLAIN_DOCS rather than shipping thin pages:")
        for r in thin:
            print(f"    {r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
