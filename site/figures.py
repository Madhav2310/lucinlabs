#!/usr/bin/env python3
"""figures.py — hand-authored inline SVG figures for the blog.

Why inline SVG and not images (the reasoning is `launch/04_BLOGS.md` §2):
zero extra requests, sharp at any DPR, the text inside is selectable and
crawlable, and the palette is inherited so figures cannot drift out of brand.

Why a Python module and not raw HTML in the markdown: `build_blog.py` parses
posts with `MarkdownIt("commonmark", {"html": False})` and renders through a
tag allow-list, so raw `<figure>` in a post is silently DROPPED. Rather than
enable raw HTML across every post, a post references a figure by id:

    ```figure
    hf-flow
    ```

and `build_blog._split_blocks` swaps that fence for `render("hf-flow")`. The
markdown stays readable, the geometry lives here, and a typo raises at build
time instead of publishing a blank space.

House rules, from §2.6 — enforced by `check()` at the bottom of this file:
  1. Every figure carries `role="img"`, a `<title>` and a `<desc>` that states
     the finding in prose. That `<desc>` is what a text-only crawler reads.
  2. Captions carry the argument, not a description of the picture.
  3. Any figure containing a measured number names its regenerating command.
"""
from __future__ import annotations

import html
import re

# ---------------------------------------------------------------- palette
# §2.1. `SAFE` is the only addition to the site palette: without a colour for
# "remediated" you cannot draw a before/after, which is the most persuasive
# figure type here.
INK = "#141414"
PAPER = "#FAF9F7"
SIGNAL = "#D6321F"
WARN = "#D69A1F"
MUTED = "#6C7076"
RULE = "#E4E1DC"
SAFE = "#2E7D53"
SURFACE = "#FFFFFF"

MONO = "IBM Plex Mono, ui-monospace, Menlo, monospace"

CSS = """<style>
.fig{margin:40px 0;border-top:1px solid #E4E1DC;border-bottom:1px solid #E4E1DC;padding:26px 0}
.fig svg{width:100%;height:auto;display:block;overflow:visible}
.fig figcaption{font-size:13px;color:#6C7076;margin-top:18px;line-height:1.55;font-family:var(--mono)}
.fig figcaption b{color:#141414;font-weight:600}
.fig figcaption code{font-family:var(--mono);font-size:.94em;color:#141414}
.fig .lbl{font-family:var(--mono);font-size:11px;fill:#6C7076}
.fig .lbl-ink{font-family:var(--mono);font-size:11px;fill:#141414}
.fig .lbl-sig{font-family:var(--mono);font-size:11px;fill:#D6321F}
.fig .lbl-safe{font-family:var(--mono);font-size:11px;fill:#2E7D53}
.fig .eyebrow{font-family:var(--mono);font-size:10px;letter-spacing:.14em;fill:#6C7076}
.fig .num{font-family:var(--mono);font-size:12px;fill:#141414}
@media (max-width:620px){.fig svg{min-width:0}.fig figcaption{font-size:12px}}
</style>"""


def _e(s: str) -> str:
    return html.escape(str(s), quote=True)


# ---------------------------------------------------------------- primitives
def txt(x, y, s, cls="lbl", anchor="middle", weight=None, size=None):
    a = f' text-anchor="{anchor}"' if anchor else ""
    w = f' font-weight="{weight}"' if weight else ""
    z = f' font-size="{size}"' if size else ""
    return f'<text x="{x}" y="{y}" class="{cls}"{a}{w}{z}>{_e(s)}</text>'


def line(x1, y1, x2, y2, stroke=INK, width=1.5, dash=None, opacity=None):
    d = f' stroke-dasharray="{dash}"' if dash else ""
    o = f' opacity="{opacity}"' if opacity is not None else ""
    return (f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{stroke}" '
            f'stroke-width="{width}"{d}{o}/>')


def rect(x, y, w, h, fill="none", stroke=None, width=1.5, rx=0, dash=None, opacity=None):
    s = f' stroke="{stroke}" stroke-width="{width}"' if stroke else ""
    d = f' stroke-dasharray="{dash}"' if dash else ""
    o = f' opacity="{opacity}"' if opacity is not None else ""
    return f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}" fill="{fill}"{s}{d}{o}/>'


def circle(cx, cy, r, fill="none", stroke=None, width=2):
    s = f' stroke="{stroke}" stroke-width="{width}"' if stroke else ""
    return f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="{fill}"{s}/>'


def arrow(x1, y1, x2, y2, stroke=INK, width=1.5, head=5):
    """A line with a solid triangular head at (x2,y2). Horizontal or vertical only."""
    if y1 == y2:
        s = 1 if x2 > x1 else -1
        tip, back = x2, x2 - s * head * 1.7
        pts = f"{tip},{y2} {back},{y2 - head} {back},{y2 + head}"
        body = line(x1, y1, back, y2, stroke, width)
    else:
        s = 1 if y2 > y1 else -1
        tip, back = y2, y2 - s * head * 1.7
        pts = f"{x2},{tip} {x2 - head},{back} {x2 + head},{back}"
        body = line(x1, y1, x2, back, stroke, width)
    return body + f'<polygon points="{pts}" fill="{stroke}"/>'


def source_node(cx, cy, label, colour=WARN, label_dy=-20):
    """A capability that introduces untrusted input: hollow ring."""
    return circle(cx, cy, 11, "none", colour, 2) + txt(cx, cy + label_dy, label)


def tool_node(cx, cy, label, fill=INK, label_dy=-20, w=34, h=26, cls="lbl"):
    """A tool: filled square, matching the landing-page hero's vocabulary."""
    return rect(cx - w / 2, cy - h / 2, w, h, fill) + txt(cx, cy + label_dy, label, cls)


def fig(fid: str, title: str, desc: str, vb: str, body: str, caption: str) -> str:
    return (
        f'<figure class="fig" id="fig-{fid}">\n'
        f'  <svg viewBox="{vb}" role="img" aria-labelledby="{fid}-t {fid}-d">\n'
        f'    <title id="{fid}-t">{_e(title)}</title>\n'
        f'    <desc id="{fid}-d">{_e(desc)}</desc>\n'
        f"    {body}\n"
        f"  </svg>\n"
        f"  <figcaption>{caption}</figcaption>\n"
        f"</figure>"
    )


def taint_wash(x1, x2, y, label="TAINT PATH · UNTRUSTED → EXTERNAL"):
    return (line(x1, y, x2, y, SIGNAL, 1, "3 4", 0.5)
            + txt((x1 + x2) / 2, y + 20, label, "lbl-sig"))


def hbars(rows, x0=150, y0=34, w=340, step=30, bar_h=13, note_x=560):
    """Horizontal bars, one quantity per row. §2.4: never stacked, never a donut."""
    out = []
    for i, (label, pct, note, colour) in enumerate(rows):
        y = y0 + i * step
        out.append(txt(x0 - 14, y + bar_h - 2, label, "lbl-ink", "end"))
        out.append(rect(x0, y, w, bar_h, RULE))
        if pct:
            out.append(rect(x0, y, w * pct / 100, bar_h, colour))
        out.append(txt(x0 + w + 14, y + bar_h - 2, f"{pct}%", "num", "start"))
        if note:
            out.append(txt(note_x, y + bar_h - 2, note, "lbl", "start"))
    return "".join(out)


def matrix(cols, rows, x0=196, y0=52, cw=132, rh=40):
    """A grid where the empty cells carry the argument."""
    out = []
    for j, c in enumerate(cols):
        for k, part in enumerate(c.split("\n")):
            out.append(txt(x0 + j * cw + cw / 2, y0 - 20 + k * 12, part, "eyebrow"))
    for i, (label, cells) in enumerate(rows):
        y = y0 + i * rh
        out.append(txt(x0 - 16, y + rh / 2 + 4, label, "lbl-ink", "end"))
        out.append(line(0, y, x0 + len(cols) * cw, y, RULE, 1))
        for j, (mark, colour) in enumerate(cells):
            cx = x0 + j * cw + cw / 2
            out.append(txt(cx, y + rh / 2 + 5, mark,
                           {"sig": "lbl-sig", "safe": "lbl-safe", "warn": "lbl"}[colour]))
    out.append(line(0, y0 + len(rows) * rh, x0 + len(cols) * cw, y0 + len(rows) * rh, RULE, 1))
    return "".join(out)


def code_panel(x, y, w, lines, accent=INK, title=None, lh=19, pad=14):
    """A code block as a figure element, with an accent rule down the left of the
    line that matters (§2.5). `lines` is a list of (text, marked)."""
    h = pad * 2 + lh * len(lines) + (22 if title else 0)
    out = [rect(x, y, w, h, SURFACE, RULE, 1, rx=3)]
    if title:
        out.append(txt(x + pad, y + pad + 8, title, "eyebrow", "start"))
    ty = y + pad + (22 if title else 0) + 11
    for i, (s, marked) in enumerate(lines):
        ly = ty + i * lh
        if marked:
            out.append(rect(x + 1, ly - 12, 3, lh, accent))
        out.append(txt(x + pad, ly, s, "lbl-ink" if marked else "lbl", "start"))
    return "".join(out), h


# ================================================================= figures
def _hf_flow():
    b = [txt(320, 18, "THE HUGGING FACE CHAIN, AS AN INFORMATION-FLOW GRAPH", "eyebrow")]
    xs = [70, 232, 394, 556]
    b += [line(xs[0] + 16, 108, xs[1] - 20, 108, INK, 1.5),
          line(xs[1] + 20, 108, xs[2] - 20, 108, INK, 1.5),
          line(xs[2] + 20, 108, xs[3] - 20, 108, SIGNAL, 2.5)]
    b.append(taint_wash(56, 584, 150))
    b.append(source_node(xs[0], 108, "load_dataset"))
    b.append(tool_node(xs[1], 108, "run_code"))
    b.append(tool_node(xs[2], 108, "read_env"))
    b.append(tool_node(xs[3], 108, "send", SIGNAL, cls="lbl-sig"))
    b += [txt(xs[0], 132, "untrusted in", "lbl"), txt(xs[3], 132, "external out", "lbl-sig")]
    return fig("hf-flow",
               "Information-flow path from an untrusted dataset to an external sink",
               "load_dataset introduces untrusted content. run_code executes it. read_env "
               "reaches credentials. send transmits externally. The path from load_dataset "
               "to send is the finding: four tools, each individually reasonable.",
               "0 0 640 176", "".join(b),
               "<b>Figure 1 — Four tools, one path.</b> Every node here is a tool somebody "
               "reviewed and approved on its own. The finding is not any node; it is the "
               "edge sequence between them.")


def _hf_mincut():
    b = [txt(160, 18, "BEFORE", "eyebrow"), txt(500, 18, "AFTER ONE CUT", "eyebrow")]
    for ox, cut in ((0, False), (340, True)):
        xs = [ox + 40, ox + 128, ox + 216, ox + 292]
        col = RULE if cut else INK
        sig = RULE if cut else SIGNAL
        b += [line(xs[0] + 13, 96, xs[1] - 18, 96, col, 1.5),
              line(xs[1] + 18, 96, xs[2] - 18, 96, col, 1.5),
              line(xs[2] + 18, 96, xs[3] - 18, 96, sig, 2.5)]
        b.append(source_node(xs[0], 96, "load_dataset", SAFE if cut else WARN, -18))
        if cut:
            b.append(circle(xs[0], 96, 17, "none", SAFE, 1.5))
        b.append(tool_node(xs[1], 96, "run_code", RULE if cut else INK, -18, 30, 24))
        b.append(tool_node(xs[2], 96, "read_env", RULE if cut else INK, -18, 30, 24))
        b.append(tool_node(xs[3], 96, "send", RULE if cut else SIGNAL, -18, 30, 24,
                           "lbl" if cut else "lbl-sig"))
        b.append(txt(ox + 168, 132, "path open" if not cut else "path broken",
                     "lbl-sig" if not cut else "lbl-safe"))
    b.append(line(320, 34, 320, 142, RULE, 1))
    return fig("hf-mincut", "The same graph before and after gating one tool",
               "On the left the exfiltration path is open across four tools. On the right "
               "load_dataset is gated, and every path through it is broken at once. One "
               "change, not four.",
               "0 0 660 156", "".join(b),
               "<b>Figure 2 — Gating one tool breaks every path.</b> The minimum cut is one "
               "node, not four. This is the difference between reporting a path and "
               "computing the fix.")


def _litellm_timeline():
    ev = [(64, "19 MAR", "Trivy", "the scanner in\nLiteLLM's own CI"),
          (222, "21 MAR", "Checkmarx AST", "GitHub Actions"),
          (380, "24 MAR", "LiteLLM", "95M downloads/mo"),
          (538, "27 MAR", "telnyx", "downstream")]
    b = [txt(300, 16, "TEAMPCP — FOUR COMPROMISES IN NINE DAYS", "eyebrow"),
         line(44, 66, 580, 66, RULE, 1.5)]
    for i, (x, d, who, note) in enumerate(ev):
        colour = SIGNAL if who == "LiteLLM" else INK
        if i:
            b.append(line(ev[i - 1][0] + 9, 66, x - 9, 66, INK if i < 3 else SIGNAL, 1.5))
        b.append(circle(x, 66, 7, colour, colour, 0))
        b.append(txt(x, 46, d, "eyebrow"))
        b.append(txt(x, 92, who, "lbl-sig" if colour == SIGNAL else "lbl-ink"))
        for k, part in enumerate(note.split("\n")):
            b.append(txt(x, 110 + k * 13, part, "lbl"))
    # The annotation spans Trivy -> LiteLLM: the scanner was the entry point into
    # LiteLLM, not into Checkmarx. Drawing it Trivy -> Checkmarx claims the wrong edge.
    b.append(line(64, 136, 380, 136, SIGNAL, 1, "3 4", .7))
    b.append(txt(222, 152, "the scanner was the way in", "lbl-sig"))
    return fig("litellm-timeline", "TeamPCP campaign timeline, 19 to 27 March 2026",
               "Four compromises in nine days: Trivy on 19 March, Checkmarx AST GitHub "
               "Actions on 21 March, LiteLLM on 24 March, telnyx on 27 March. The entry "
               "point into LiteLLM was Trivy, the security scanner running in its pipeline.",
               "0 0 620 164", "".join(b),
               "<b>Figure 1 — The way into LiteLLM was a security scanner.</b> That is the "
               "uncomfortable part, and it is the strongest available argument for a local, "
               "auditable, MIT-licensed scanner over a SaaS agent holding CI credentials.")


def _litellm_pth():
    steps = [("pip install litellm", "unpinned resolve picks 1.82.7", INK),
             ("sdist ships a .pth file", "written into site-packages/", INK),
             ("python starts", "site.py executes every .pth line", WARN),
             ("harvester runs", "before any import in your code", SIGNAL)]
    b = [txt(300, 16, "WHY A .PTH FILE RUNS BEFORE YOUR FIRST IMPORT", "eyebrow")]
    for i, (head, sub, colour) in enumerate(steps):
        y = 46 + i * 44
        b.append(rect(40, y, 14, 14, colour))
        b.append(txt(70, y + 12, head, "lbl-ink", "start"))
        b.append(txt(330, y + 12, sub, "lbl", "start"))
        if i < 3:
            b.append(arrow(47, y + 18, 47, y + 40, RULE, 1.5, 4))
    b.append(line(28, 218, 580, 218, RULE, 1))
    b.append(txt(40, 238, "A .pth line beginning with 'import' is executed by the "
                          "interpreter at startup.", "lbl", "start"))
    return fig("litellm-pth", "The .pth autorun mechanism",
               "An unpinned install resolves to the malicious version. Its sdist writes a "
               ".pth file into site-packages. Python's site module executes any .pth line "
               "starting with import, at interpreter startup, before user code runs.",
               "0 0 620 252", "".join(b),
               "<b>Figure 2 — The payload never needed you to import it.</b> A <code>.pth</code> "
               "line runs at interpreter startup, which is why 'we don't call that library "
               "directly' is not a mitigation.")


def _dep_graph(pinned: bool):
    top = [(96, "agent app"), (232, "MCP server"), (368, "orchestrator"), (504, "notebook")]
    colour = SAFE if pinned else SIGNAL
    b = [txt(300, 16, "PINNED — RESOLVES TO A KNOWN VERSION" if pinned
             else "UNPINNED — RESOLVES TO WHATEVER IS NEWEST", "eyebrow")]
    for x, lbl in top:
        b.append(tool_node(x, 62, lbl, INK, -20, 30, 24))
        b.append(line(x, 76, 300, 132, RULE if pinned else SIGNAL, 1.2))
    b.append(rect(238, 132, 124, 34, colour, rx=2))
    b.append(txt(300, 154, "litellm", "lbl", size=12) .replace('class="lbl"', 'class="lbl" fill="#fff"'))
    b.append(txt(300, 188, "litellm==1.82.6" if pinned else "litellm  (any)",
                 "lbl-safe" if pinned else "lbl-sig"))
    b.append(txt(300, 208, "1.82.7 cannot be selected" if pinned
                 else "1.82.7 is selected for 40 minutes", "lbl"))
    return b


def _litellm_depgraph():
    return fig("litellm-depgraph", "LiteLLM's position beneath the agent ecosystem",
               "Four kinds of downstream consumer — an agent app, an MCP server, an "
               "orchestrator and a notebook — all resolve litellm transitively. With no "
               "version pin, each of them selects the newest release available.",
               "0 0 620 224", "".join(_dep_graph(False)),
               "<b>Figure 3 — One unpinned edge, four blast radii.</b> None of these projects "
               "depends on <code>litellm</code> deliberately; they depend on something that does.")


def _litellm_pinned():
    return fig("litellm-pinned", "The same dependency graph with a version pin applied",
               "With litellm pinned to 1.82.6, the malicious 1.82.7 release cannot be "
               "selected by any of the four downstream consumers. The graph is unchanged; "
               "only the resolution rule differs.",
               "0 0 620 224", "".join(_dep_graph(True)),
               "<b>Figure 4 — The same graph, pinned.</b> The fix is not new architecture. "
               "It is a constraint, which is exactly the kind of thing a scanner can check "
               "mechanically — <code>AG-FRAMEWORK-PIN</code>.")


def _recall_bars():
    # Verified against a live run: `python benchmarks/recall_corpus.py`, 2026-08-06.
    rows = [("path traversal", 0, "detector built, unregistered", SIGNAL),
            ("SSRF", 17, "fires only on the URL host", SIGNAL),
            ("container escape", 80, "1 miss: fired AG-001 instead", WARN),
            ("CQL injection", 100, "", INK),
            ("command injection", 100, "", INK),
            ("CORS / unauth server", 100, "", INK),
            ("insecure deserialization", 100, "", INK),
            ("RCE via eval/exec", 100, "", INK),
            ("secret exfiltration", 100, "", INK),
            ("SQL injection", 100, "", INK)]
    b = [txt(182, 16, "RECALL BY CLASS — SORTED WORST FIRST", "eyebrow", "start"),
         hbars(rows, x0=182, y0=32, w=276, step=28, note_x=500),
         line(182, 318, 458, 318, RULE, 1),
         txt(174, 334, "OVERALL", "lbl-ink", "end", 600),
         txt(182, 334, "38 / 50 = 76%   ·   12 misses, all named below", "lbl", "start")]
    return fig("recall-bars", "Lucin's recall by vulnerability class, sorted worst first",
               "Two classes fail: path traversal at 0 percent because the detector is "
               "deliberately unregistered, and SSRF at 17 percent because it only fires when "
               "taint forms the URL host. Six classes are at 100 percent and container "
               "escape at 80. Overall recall is 38 of 50, or 76 percent.",
               "0 0 700 344", "".join(b),
               "<b>Figure 1 — Sorted worst-first, because that is the order that tells you "
               "something.</b> An aggregate of 76% hides the shape completely. "
               "Regenerate: <code>python benchmarks/recall_corpus.py</code>")


def _path_traversal_ambiguity():
    benign, hb = code_panel(24, 40, 292, [
        ("def read_template(name):", False),
        ("    p = os.path.join(BASE, name)", True),
        ("    return open(p).read()", False)], SAFE, "LEGITIMATE — IN THE BENIGN CORPUS")
    mal, _ = code_panel(348, 40, 292, [
        ("def read_document(name):", False),
        ("    p = os.path.join(BASE, name)", True),
        ("    return open(p).read()", False)], SIGNAL, "VULNERABLE — IN THE RECALL CORPUS")
    y = 40 + hb + 26
    ast = ["Call(join) → Name(BASE) → Name(name)", "→ Call(open) → Attribute(read)"]
    b = [benign, mal, txt(170, y, "AST", "eyebrow"), txt(494, y, "AST", "eyebrow")]
    for cx in (170, 494):
        for k, part in enumerate(ast):
            b.append(txt(cx, y + 20 + k * 15, part, "lbl", size=9))
    y += 15
    b += [line(24, y + 38, 640, y + 38, RULE, 1),
          txt(332, y + 60, "structurally identical — no static rule separates them", "lbl-sig")]
    return fig("path-traversal-ambiguity",
               "A benign file tool and a vulnerable one, with identical structure",
               "Both functions join a caller-supplied name onto a base directory and open "
               "the result. Their abstract syntax trees are the same sequence of nodes. A "
               "detector that fires on one necessarily fires on the other.",
               f"0 0 664 {y + 76}", "".join(b),
               "<b>Figure 2 — The detector is off because these are the same program.</b> "
               "Registering it would have caught the case on the right and every case on "
               "the left. That trade costs 6 of 50 cases — 12% of headline recall. "
               "Regenerate: <code>python benchmarks/recall_corpus.py</code>")


def _cve_lc_path():
    b = [txt(320, 16, "CVE-2025-68664 — THE ESCAPE IS MISSING ON THE WAY OUT", "eyebrow")]
    xs = [78, 246, 414, 570]
    b += [line(xs[0] + 16, 96, xs[1] - 22, 96, INK, 1.5),
          line(xs[1] + 22, 96, xs[2] - 22, 96, SIGNAL, 2.5),
          line(xs[2] + 22, 96, xs[3] - 20, 96, SIGNAL, 2.5)]
    b.append(source_node(xs[0], 96, "user dict"))
    b.append(txt(xs[0], 120, 'contains an "lc" key', "lbl"))
    b.append(tool_node(xs[1], 96, "dumps()", INK, -20, 40, 26))
    b.append(tool_node(xs[2], 96, "loads()", SIGNAL, -20, 40, 26, "lbl-sig"))
    b.append(tool_node(xs[3], 96, "class rebuilt", SIGNAL, -20, 40, 26, "lbl-sig"))
    b.append(rect(xs[1] - 44, 128, 88, 20, SIGNAL, rx=2))
    b.append(txt(xs[1], 142, "no escape", "lbl", size=10).replace('class="lbl"', 'class="lbl" fill="#fff"'))
    b.append(txt(xs[1], 168, "the bug is HERE — in serialization", "lbl-sig"))
    b.append(txt(xs[2], 168, "not here", "lbl"))
    return fig("cve-lc-path", "Where CVE-2025-68664 actually goes wrong",
               "A user-supplied dictionary containing an lc key passes through dumps, which "
               "fails to escape it. loads then treats the attacker's key as a serialization "
               "directive and reconstructs an arbitrary class. The defect is in the "
               "serialization path, not the deserialization path.",
               "0 0 640 184", "".join(b),
               "<b>Figure 1 — The flaw is in <code>dumps()</code>, not <code>loads()</code>.</b> "
               "That distinction is the whole advisory: hardening your deserializer does not "
               "help, because the payload was made trustworthy on the way out.")


def _cve_annotated_code():
    panel, h = code_panel(24, 34, 616, [
        ("def _metadata_predicate(filter_key, filter_value):", False),
        ('    predicate = f"metadata->>\'$.{filter_key}\' = ?"', True),
        ("    #                            ^^^^^^^^^^ caller-controlled", False),
        ("    return predicate, [filter_value]   # value IS parameterised", False)],
        SIGNAL, "CVE-2025-67644 — LANGGRAPH CHECKPOINT FILTER")
    y = 34 + h + 26
    b = [panel,
         txt(24, y, "the value is safe", "lbl-safe", "start"),
         txt(24, y + 18, "the key is interpolated", "lbl-sig", "start"),
         line(300, y - 12, 300, y + 24, RULE, 1),
         txt(320, y, "Parameterising values is the standard fix and it is", "lbl", "start"),
         txt(320, y + 18, "already applied here. It does not reach the key.", "lbl", "start")]
    return fig("cve-annotated-code", "The injection point in CVE-2025-67644 is the filter key",
               "The function interpolates the caller-controlled filter key directly into an "
               "f-string used as SQL, while correctly parameterising the filter value. "
               "Because the injection point is the key rather than the value, parameterised "
               "queries do not mitigate it.",
               f"0 0 664 {y + 34}", "".join(b),
               "<b>Figure 2 — The mitigation everyone already applied does not apply here.</b> "
               "Maps to <code>AG-SQL</code>.")


def _cve_reachability():
    rows = [("CVE-2025-68664", [("reachable", "sig"), ("reachable", "sig"), ("reachable", "sig")]),
            ("CVE-2025-67644", [("reachable", "sig"), ("not affected", "safe"), ("not affected", "safe")]),
            ("CVE-2026-34070", [("conditional", "warn"), ("conditional", "warn"), ("conditional", "warn")]),
            ("CVE-2026-28277", [("chains → RCE", "sig"), ("not affected", "safe"), ("not affected", "safe")])]
    b = [txt(20, 18, "REACHABILITY BY DEPLOYMENT SHAPE", "eyebrow", "start"),
         matrix(["SELF-HOSTED\nSQLITE", "SELF-HOSTED\nPOSTGRES", "MANAGED\nLANGSMITH"],
                rows, x0=196, y0=56, cw=150, rh=42),
         txt(20, 258, "conditional = legacy load_prompt only, and reads are restricted to "
                      ".txt / .json / .yaml", "lbl", "start")]
    return fig("cve-reachability", "Which of the four CVEs is reachable in which deployment",
               "CVE-2025-68664 is reachable everywhere. CVE-2025-67644 and the msgpack chain "
               "CVE-2026-28277 affect only self-hosted SQLite deployments; LangSmith "
               "Deployment runs PostgreSQL and is not affected. CVE-2026-34070 is "
               "conditional everywhere and limited by an extension allowlist.",
               "0 0 664 274", "".join(b),
               "<b>Figure 3 — Being precise about who is <i>not</i> vulnerable is the "
               "cheapest credibility available.</b> Three of these four do not reach a "
               "managed deployment at all.")


def _prose_checker_vs_agent():
    left, h = code_panel(24, 44, 300, [
        ("read('./docs/notes.md')", True),
        ("deny: ['/etc/**', '~/.ssh/**']", False),
        ("match? no", False),
        ("verdict: ALLOWED", False)], SAFE, "WHAT THE CHECKER SEES")
    right, _ = code_panel(364, 44, 300, [
        ("./docs/notes.md", True),
        ("  -> symlink ->", False),
        ("~/.ssh/id_ed25519", False),
        ("verdict: (never asked)", False)], SIGNAL, "WHAT THE AGENT REACHES")
    y = 44 + h + 24
    b = [txt(174, 22, "ONE OPERATION", "eyebrow"), txt(514, 22, "TWO OBJECTS", "eyebrow"),
         left, right,
         arrow(330, 44 + h / 2, 358, 44 + h / 2, RULE, 1.5, 4),
         line(24, y + 6, 664, y + 6, RULE, 1),
         txt(24, y + 28, "the rule answered its question correctly — it was the wrong question",
             "lbl-sig", "start")]
    return fig("prose-checker-vs-agent",
               "The permission checker and the agent are looking at different objects",
               "The deny rule is evaluated against the literal path string, which does not "
               "match. The agent then follows the symlink and reads the private key. Both "
               "steps behave as designed; the identifier the checker sees has diverged from "
               "the resource the agent reaches.",
               f"0 0 688 {y + 44}", "".join(b),
               "<b>Figure 1 — The rule answered its question correctly.</b> Deny-lists "
               "operate on identifiers; agents operate on intent. Every layer of indirection "
               "is a place those two can diverge.")


def _prose_containment():
    b = [txt(160, 18, "WITH AN EGRESS TOOL", "eyebrow"),
         txt(510, 18, "EGRESS GATED", "eyebrow")]
    for ox, gated in ((0, False), (340, True)):
        xs = [ox + 52, ox + 160, ox + 272]
        b.append(source_node(xs[0], 96, "read()", WARN, -20))
        b.append(tool_node(xs[1], 96, "id_ed25519", INK, -20, 30, 24))
        b.append(line(xs[0] + 13, 96, xs[1] - 17, 96, INK, 1.5))
        if gated:
            b.append(line(xs[1] + 17, 96, xs[2] - 16, 96, RULE, 1.5, "4 4"))
            b.append(circle(xs[2], 96, 13, "none", SAFE, 2))
            b.append(txt(xs[2], 72, "send", "lbl-safe"))
            b.append(txt(ox + 168, 138, "read succeeds, nothing leaves", "lbl-safe"))
        else:
            b.append(line(xs[1] + 17, 96, xs[2] - 16, 96, SIGNAL, 2.5))
            b.append(tool_node(xs[2], 96, "send", SIGNAL, -20, 30, 24, "lbl-sig"))
            b.append(txt(ox + 168, 138, "read succeeds, key leaves", "lbl-sig"))
    b.append(line(320, 40, 320, 150, RULE, 1))
    return fig("prose-containment", "The same successful read with and without an egress path",
               "In both configurations the symlink read succeeds — the attack works. On the "
               "left the agent also holds a send tool, so the key leaves. On the right the "
               "egress tool is gated, so the read terminates locally and the consequence is "
               "bounded.",
               "0 0 660 164", "".join(b),
               "<b>Figure 2 — The same successful attack, two outcomes.</b> Static analysis "
               "cannot tell you whether a comment is adversarial. It can bound what happens "
               "when one works — cutting capability rather than predicting intent.")


def _benchmark_grid():
    # This renders the table immediately above it in the post. Rows, columns and
    # cell values must stay in step with that table — including Vendor A, which
    # does claim an FP rate, and so is not an empty cell.
    E = ("—", "sig")
    Y = ("yes", "safe")
    rows = [("public corpus", [E, E, E, E, Y]),
            ("per-class recall", [E, E, E, E, Y]),
            ("precision + rubric", [("claimed", "warn"), E, E, E, Y]),
            ("false-negative list", [E, E, E, E, ("all 12", "safe")]),
            ("one command", [E, E, E, E, Y])]
    b = [txt(20, 18, "WHAT EACH TOOL PUBLISHES THAT YOU CAN CHECK", "eyebrow", "start"),
         matrix(["VENDOR A", "VENDOR B", "VENDOR C", "VENDOR D", "LUCIN"], rows,
                x0=190, y0=54, cw=100, rh=34),
         txt(20, 258, "Assembled from public marketing pages. Every vendor performance "
                      "figure is a claim, unverified.", "lbl", "start")]
    return fig("benchmark-grid", "What each scanner publishes that a reader can verify",
               "Across the five properties a benchmark would require — a public corpus, "
               "per-class recall, precision with an adjudication rubric, a published "
               "false-negative list and a single reproducing command — the four vendor "
               "columns are empty apart from one claimed false-positive rate, and the "
               "Lucin column is filled.",
               "0 0 700 274", "".join(b),
               "<b>Figure 1 — The empty cells are the argument.</b> Assembled from public "
               "marketing pages; the vendor figures are claims, not measurements.")


def _trifecta_three():
    caps = [(96, "READS", "an input it trusts", "read_email · fetch_url", WARN),
            (320, "TOUCHES", "something worth taking", "query_customers", INK),
            (544, "SENDS", "a way out", "post_webhook · git_push", SIGNAL)]
    b = [txt(320, 16, "EACH ONE IS COMPLETELY FINE ALONE", "eyebrow")]
    for i, (x, k, t, ex, colour) in enumerate(caps):
        b.append(rect(x - 96, 38, 192, 84, SURFACE, colour, 1.5, rx=3))
        b.append(txt(x, 60, k, "eyebrow"))
        b.append(txt(x, 82, t, "lbl-ink"))
        b.append(txt(x, 104, ex, "lbl"))
        if i:
            b.append(line(caps[i - 1][0] + 96, 80, x - 96, 80, SIGNAL, 1.5))
    b.append(txt(320, 150, "all three, reachable in one run  =  an exfiltration path",
                 "lbl-sig"))
    return fig("trifecta-three", "The three capabilities that compose into an exfiltration",
               "A tool that reads untrusted input, a tool that touches private data, and a "
               "tool that can send externally. Each is a reasonable capability on its own. "
               "The risk appears only when all three are reachable within a single agent run.",
               "0 0 660 168", "".join(b),
               "<b>Figure 1 — Nobody approved the combination.</b> Every tool here passed "
               "review individually, which is exactly why per-tool review does not find this.")


def _aifg_lattice():
    b = [txt(160, 16, "THE LABEL LATTICE", "eyebrow"),
         txt(500, 16, "THE QUERY", "eyebrow")]
    pts = [(160, 56, "SECRET"), (100, 108, "PRIVATE"), (220, 108, "UNTRUSTED"), (160, 160, "PUBLIC")]
    for x, y, lbl in pts:
        b.append(rect(x - 52, y - 14, 104, 28, SURFACE, INK, 1.5, rx=3))
        b.append(txt(x, y + 5, lbl, "lbl-ink"))
    b += [line(160, 70, 100, 94, INK, 1.2), line(160, 70, 220, 94, INK, 1.2),
          line(100, 122, 160, 146, INK, 1.2), line(220, 122, 160, 146, INK, 1.2)]
    b.append(txt(160, 192, "join = least upper bound", "lbl"))
    b.append(line(320, 40, 320, 200, RULE, 1))
    b += [txt(500, 56, "is there a path", "lbl-ink"),
          txt(500, 76, "from any UNTRUSTED source", "lbl-sig"),
          txt(500, 96, "to any external sink", "lbl-sig"),
          txt(500, 116, "that no barrier dominates?", "lbl-ink"),
          line(400, 134, 600, 134, RULE, 1),
          txt(500, 156, "reachability, not simulation", "lbl"),
          txt(500, 176, "answerable · decidable · fast", "lbl-safe")]
    return fig("aifg-lattice", "The information-flow label lattice and the reachability query",
               "Labels form a four-point lattice from PUBLIC up through PRIVATE and "
               "UNTRUSTED to SECRET, joined by least upper bound. The analysis reduces to a "
               "reachability question over the tool graph: does an untrusted source reach an "
               "external sink without passing a barrier.",
               "0 0 660 212", "".join(b),
               "<b>Figure 1 — The whole engine is a reachability query over a lattice.</b> "
               "Not simulation, not prediction — which is why it terminates, and also why "
               "there are questions it provably cannot answer.")


def _aifg_mincut():
    b = [txt(320, 16, "SIXTEEN PATHS, ONE CUT VERTEX", "eyebrow")]
    srcs = [(70, 56), (70, 100), (70, 144)]
    sinks = [(570, 56), (570, 100), (570, 144)]
    for x, y in srcs:
        b.append(circle(x, y, 9, "none", WARN, 2))
        b.append(line(x + 9, y, 292, 100, SIGNAL, 1, None, .45))
    for x, y in sinks:
        b.append(rect(x - 15, y - 12, 30, 24, SIGNAL))
        b.append(line(348, 100, x - 15, y, SIGNAL, 1, None, .45))
    b.append(rect(292, 78, 56, 44, INK, rx=3))
    b.append(txt(320, 105, "__llm__", "lbl", size=10).replace('class="lbl"', 'class="lbl" fill="#fff"'))
    b.append(circle(320, 100, 34, "none", SAFE, 2))
    b.append(txt(320, 168, "cut here", "lbl-safe"))
    b += [txt(70, 190, "3 untrusted sources", "lbl"), txt(570, 190, "3 external sinks", "lbl")]
    return fig("aifg-mincut", "A minimum vertex cut on the agent's information-flow graph",
               "Three untrusted sources and three external sinks yield many distinct paths, "
               "all of which pass through a single node. Removing or gating that one vertex "
               "severs every path simultaneously.",
               "0 0 660 204", "".join(b),
               "<b>Figure 2 — A list of paths is not a fix; the cut vertex is.</b> This is "
               "the computation no competing scanner performs, because none of them model "
               "tool composition at all.")


def _benchmark_two_questions():
    b = [txt(170, 16, "PRECISION ASKS", "eyebrow"), txt(500, 16, "RECALL ASKS", "eyebrow"),
         rect(24, 34, 292, 108, SURFACE, INK, 1.5, rx=3),
         rect(348, 34, 292, 108, SURFACE, INK, 1.5, rx=3),
         txt(170, 66, "of the things we flagged,", "lbl-ink"),
         txt(170, 86, "how many were real?", "lbl-ink"),
         txt(170, 116, "denominator: our findings", "lbl"),
         txt(500, 66, "of the things that were real,", "lbl-ink"),
         txt(500, 86, "how many did we flag?", "lbl-ink"),
         txt(500, 116, "denominator: known vulns", "lbl"),
         line(24, 166, 640, 166, RULE, 1),
         txt(332, 190, "different denominators — a single accuracy number hides both",
             "lbl-sig")]
    return fig("benchmark-two-questions",
               "Precision and recall answer different questions with different denominators",
               "Precision divides by the findings the tool produced; recall divides by the "
               "vulnerabilities known to exist. Because the denominators differ, no single "
               "accuracy figure can stand in for both.",
               "0 0 664 206", "".join(b),
               "<b>Figure 1 — Two questions, two denominators.</b> A vendor quoting one "
               "number is choosing which question you are allowed to ask.")


def _trifecta_shaped_wired():
    b = [txt(160, 16, "SHAPED — ARITHMETIC", "eyebrow"),
         txt(500, 16, "WIRED — YOUR CODE", "eyebrow"),
         txt(160, 92, "64", "lbl-ink", size=54, weight=700),
         txt(500, 92, "1", "lbl-sig", size=54, weight=700),
         txt(160, 122, "triples with the right shape", "lbl"),
         txt(500, 122, "reachable in a single run", "lbl"),
         line(320, 34, 320, 140, RULE, 1),
         line(24, 158, 640, 158, RULE, 1),
         txt(332, 182, "the gap between those two numbers is the entire problem", "lbl-ink")]
    for i in range(8):
        b.append(rect(60 + i * 26, 132, 18, 4, RULE))
    b.append(rect(492, 132, 18, 4, SIGNAL))
    return fig("trifecta-shaped-wired",
               "Sixty-four combinations have the trifecta shape; one is actually wired",
               "In a fourteen-tool agent, sixty-four distinct triples pair an untrusted "
               "reader with a data reader and an external sender. Only one of those triples "
               "is registered to the same agent and reachable within a single run without a "
               "human in between.",
               "0 0 664 198", "".join(b),
               "<b>Figure 2 — Sixty-four is a list nobody triages. One is a decision.</b> "
               "Counting capability combinations is arithmetic; checking which are wired "
               "requires reading the tool definitions, the agent graph and the MCP config.")


def _benchmark_fp_corpus():
    b = [txt(20, 16, "BENIGN CORPUS — 54 REAL REPOSITORIES, 9,520 FILES", "eyebrow", "start")]
    for i in range(54):
        x, y = 24 + (i % 18) * 34, 44 + (i // 18) * 34
        clean = i >= 9
        b.append(rect(x, y, 24, 24, SURFACE if clean else SIGNAL,
                      RULE if clean else SIGNAL, 1, rx=2))
    b += [txt(24, 168, "45 of 54 scan completely clean", "lbl-ink", "start"),
          txt(24, 190, "9 repos produced 11 adjudicated false positives", "lbl-sig", "start"),
          line(24, 208, 640, 208, RULE, 1),
          txt(24, 230, "This answers one question — how noisy is Lucin on code chosen to be "
                       "clean — and no others.", "lbl", "start")]
    return fig("benchmark-fp-corpus", "False positives across the 54-repository benign corpus",
               "Each square is one repository. Forty-five produce no findings at all. Nine "
               "produce a total of eleven adjudicated false positives. The corpus was "
               "curated to be clean, which bounds what the result can be used to claim.",
               "0 0 664 246", "".join(b),
               "<b>Figure 2 — A good number, on a corpus chosen to be clean.</b> "
               "Regenerate: <code>python benchmarks/build_benign_corpus.py</code>")


def _benchmark_scorecard():
    rows = [("overall recall", 76, "38 / 50", INK),
            ("recall, real cases only", 86, "19 / 22", INK),
            ("path traversal", 0, "detector unregistered", SIGNAL),
            ("SSRF", 17, "host-position taint only", SIGNAL)]
    b = [txt(196, 16, "THE FIRST SUBMISSION IS OURS", "eyebrow", "start"),
         hbars(rows, x0=196, y0=36, w=252, step=32, note_x=508),
         line(196, 168, 448, 168, RULE, 1),
         txt(20, 196, "Submitting your own tool first, including the two rows that fail,",
             "lbl", "start"),
         txt(20, 212, "is the entry fee for proposing a standard.", "lbl", "start")]
    return fig("benchmark-scorecard", "Lucin's own scores against the proposed benchmark",
               "Overall recall is 76 percent and 86 percent on real third-party cases only. "
               "Two classes fail outright: path traversal at zero because the detector is "
               "deliberately unregistered, and SSRF at seventeen percent because it fires "
               "only when taint reaches the URL host.",
               "0 0 700 226", "".join(b),
               "<b>Figure 2 — Including the two rows that fail.</b> "
               "Regenerate: <code>python benchmarks/recall_corpus.py</code>")


FIGURES = {
    "trifecta-shaped-wired": _trifecta_shaped_wired,
    "benchmark-fp-corpus": _benchmark_fp_corpus,
    "benchmark-scorecard": _benchmark_scorecard,
    "hf-flow": _hf_flow, "hf-mincut": _hf_mincut,
    "litellm-timeline": _litellm_timeline, "litellm-pth": _litellm_pth,
    "litellm-depgraph": _litellm_depgraph, "litellm-pinned": _litellm_pinned,
    "recall-bars": _recall_bars, "path-traversal-ambiguity": _path_traversal_ambiguity,
    "cve-lc-path": _cve_lc_path, "cve-annotated-code": _cve_annotated_code,
    "cve-reachability": _cve_reachability,
    "prose-checker-vs-agent": _prose_checker_vs_agent, "prose-containment": _prose_containment,
    "benchmark-grid": _benchmark_grid, "trifecta-three": _trifecta_three,
    "aifg-lattice": _aifg_lattice, "aifg-mincut": _aifg_mincut,
    "benchmark-two-questions": _benchmark_two_questions,
}


def render(fid: str) -> str:
    fid = fid.strip()
    if fid not in FIGURES:
        raise SystemExit(
            f"figures.py: unknown figure id {fid!r}. Known ids: "
            f"{', '.join(sorted(FIGURES))}"
        )
    return FIGURES[fid]()


def check() -> list[str]:
    """§2.6 as a gate, so a lazy figure cannot ship."""
    errs = []
    for fid in sorted(FIGURES):
        svg = render(fid)
        if 'role="img"' not in svg:
            errs.append(f"{fid}: no role=img")
        if "<title" not in svg or "<desc" not in svg:
            errs.append(f"{fid}: missing <title> or <desc>")
        desc = re.search(r"<desc[^>]*>(.*?)</desc>", svg, re.S)
        if not desc or len(desc.group(1).split()) < 20:
            errs.append(f"{fid}: <desc> must state the finding in prose (>=20 words)")
        cap = re.search(r"<figcaption>(.*?)</figcaption>", svg, re.S)
        if not cap or "<b>" not in cap.group(1):
            errs.append(f"{fid}: caption must lead with a bolded argument")
        if re.search(r"\b\d+\s*%", svg) and "Regenerate" not in svg and "regenerate" not in svg:
            errs.append(f"{fid}: contains a measured number but names no regenerating command")
    return errs


if __name__ == "__main__":
    problems = check()
    print(f"figures: {len(FIGURES)}")
    for p in problems:
        print(f"  [FAIL] {p}")
    print("PASS" if not problems else f"FAIL — {len(problems)} issue(s)")
    raise SystemExit(1 if problems else 0)
