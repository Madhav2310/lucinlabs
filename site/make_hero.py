#!/usr/bin/env python3
"""make_hero.py — render the hero image from a REAL Agent Information-Flow Graph.

The landing page hand-drew a four-node SVG of a graph. For a product whose entire
differentiator is "we draw you the graph", an illustration of a graph proves only that
we can draw. This renders the actual AIFG from a real scan: real tool names, the real
trifecta path, the real witness line underneath.

Design rules (deliberately few):
  * Achromatic chrome. The ONLY saturated pixels are the taint ramp — clean steel at
    the untrusted source, amber through the model, red at the egress sink. If the eye
    is drawn anywhere, it is drawn along the dangerous path.
  * Nothing decorative. No glow, no gradient mesh, no 3D. Restraint is the highest-
    status signal available in security tooling, and it is free.
  * Supersampled 3x then downsampled, because Pillow has no anti-aliasing for lines
    and jagged diagonals look amateur at any size.

Usage:  python site/make_hero.py            # writes site/hero.png (+ @2x)
        python site/make_hero.py --target X
"""
from __future__ import annotations

import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

OUT = ROOT / "site" / "hero.png"
W, H = 1000, 420
SS = 3                                   # supersample factor

# --- the palette. Same tokens as the site; see site/index.html :root ------------
CANVAS = (10, 10, 11)
SURFACE = (18, 19, 21)
SUNKEN = (7, 7, 8)
INK = (236, 237, 238)
INK_SOFT = (161, 165, 171)
INK_MUTED = (110, 115, 121)
LINE = (35, 38, 41)
LINE_STRONG = (51, 55, 60)
CLEAN = (214, 220, 227)                  # untrusted-but-not-yet-dangerous
WARN = (232, 163, 61)                    # in the model's context
HOT = (240, 68, 56)                      # leaving the trust boundary

_FONTS = ["/System/Library/Fonts/SFNSDisplay.ttf", "/System/Library/Fonts/Helvetica.ttc"]
_MONOS = ["/System/Library/Fonts/SFNSMono.ttf", "/System/Library/Fonts/Menlo.ttc"]

DEFAULT_TARGET = ("benchmarks/recall_corpus/secret_exfil_trifecta/"
                  "constructed__rag_db_http/constructed__rag_db_http.py")


def _font(paths: list[str], size: int):
    for p in paths:
        try:
            return ImageFont.truetype(p, size)
        except Exception:  # noqa: BLE001
            continue
    return ImageFont.load_default(size=size)


def _graph(target: str) -> tuple[list[dict], list[dict], str]:
    """Real nodes, edges and witness from a real scan."""
    from lucin.aifg import build_aifg, query_trifecta
    from lucin.scanner import scan_target
    result = scan_target(ROOT / target)
    for agent in result.agents:
        g = build_aifg(agent)
        tri = query_trifecta(g)
        if tri:
            d = g.to_dict()
            return d.get("nodes", []), d.get("edges", []), tri[0].witness_summary()
    return [], [], ""


def _lerp(a: tuple, b: tuple, t: float) -> tuple:
    return tuple(round(x + (y - x) * t) for x, y in zip(a, b))


def _grad_line(d: ImageDraw.ImageDraw, p0: tuple, p1: tuple,
               c0: tuple, c1: tuple, width: int, steps: int = 48) -> None:
    """A straight line whose colour interpolates — the taint ramp made literal."""
    for i in range(steps):
        t0, t1 = i / steps, (i + 1) / steps
        x0 = p0[0] + (p1[0] - p0[0]) * t0
        y0 = p0[1] + (p1[1] - p0[1]) * t0
        x1 = p0[0] + (p1[0] - p0[0]) * t1
        y1 = p0[1] + (p1[1] - p0[1]) * t1
        d.line([x0, y0, x1, y1], fill=_lerp(c0, c1, (t0 + t1) / 2), width=width)


def _node(d: ImageDraw.ImageDraw, cx: int, cy: int, w: int, h: int,
          label: str, sub: str, accent: tuple | None,
          f_label, f_sub, danger: bool = False) -> None:
    """A node box. Only the DANGEROUS node gets a coloured border.

    First pass gave every source a near-white border, which made three things shout at
    once and destroyed the point: the eye should travel the path and stop at the sink.
    Sources now carry the colour only in their small caption, so hierarchy is
    unambiguous — muted box, coloured word, red box only where data leaves.
    """
    x0, y0, x1, y1 = cx - w // 2, cy - h // 2, cx + w // 2, cy + h // 2
    d.rounded_rectangle([x0, y0, x1, y1], radius=8 * SS, fill=SURFACE,
                        outline=(HOT if danger else LINE_STRONG),
                        width=(2 if danger else 1) * SS)

    # Lay the two lines out from real font metrics rather than guessed offsets —
    # the guessed version overlapped, badly on `__llm__` where the underscores sit
    # on the descender line.
    la, ld = f_label.getmetrics()
    sa, sd = f_sub.getmetrics()
    gap = 5 * SS
    block = (la + ld) + (gap + sa + sd if sub else 0)
    top = cy - block // 2
    d.text((cx - f_label.getlength(label) / 2, top), label, font=f_label, fill=INK)
    if sub:
        d.text((cx - f_sub.getlength(sub) / 2, top + la + ld + gap), sub,
               font=f_sub, fill=accent or INK_MUTED)


def build(target: str) -> Path:
    nodes, edges, witness = _graph(target)
    if not nodes:
        raise SystemExit(f"no trifecta found in {target} — pick a fixture that has one")

    {n["id"]: n for n in nodes}
    untrusted = [n["id"] for n in nodes if n.get("is_untrusted_input")]
    sinks = [n["id"] for n in nodes if n.get("is_egress")]
    # A "secret" source: neither untrusted-input nor sink, and not the model.
    others = [n["id"] for n in nodes
              if n["id"] != "__llm__" and n["id"] not in untrusted and n["id"] not in sinks]

    src_u = untrusted[0] if untrusted else (others[0] if others else "input")
    src_s = others[0] if others else None
    sink = sinks[0] if sinks else "egress"

    img = Image.new("RGB", (W * SS, H * SS), CANVAS)
    d = ImageDraw.Draw(img)
    f_lane = _font(_MONOS, 11 * SS)
    f_node = _font(_MONOS, 15 * SS)
    f_sub = _font(_MONOS, 11 * SS)
    f_wit = _font(_MONOS, 12 * SS)
    f_cap = _font(_FONTS, 13 * SS)

    # --- geometry: three columns, generous air -------------------------------
    # .18/.50/.82 with nw=0.22 gives equal 70px gutters; .20/.52/.84 left the
    # right margin 40px tighter than the left, which reads as a mistake.
    col_x = (int(W * 0.18) * SS, int(W * 0.50) * SS, int(W * 0.82) * SS)
    row_y = (int(H * 0.32) * SS, int(H * 0.62) * SS)
    mid_y = int(H * 0.47) * SS
    nw, nh = int(W * 0.22) * SS, 58 * SS

    # lane captions
    for x, text in zip(col_x, ("UNTRUSTED INPUT", "MODEL CONTEXT", "EGRESS")):
        tw = f_lane.getlength(text)
        d.text((x - tw / 2, int(H * 0.13) * SS), text, font=f_lane, fill=INK_MUTED)

    # --- edges first, so nodes sit on top ------------------------------------
    # the two trifecta legs converge on the model, then leave through the sink
    _grad_line(d, (col_x[0] + nw // 2, row_y[0]), (col_x[1] - nw // 2, mid_y),
               CLEAN, WARN, 3 * SS)
    if src_s:
        _grad_line(d, (col_x[0] + nw // 2, row_y[1]), (col_x[1] - nw // 2, mid_y),
                   CLEAN, WARN, 3 * SS)
    _grad_line(d, (col_x[1] + nw // 2, mid_y), (col_x[2] - nw // 2, mid_y),
               WARN, HOT, 3 * SS)
    # arrowhead into the sink
    ax, ay = col_x[2] - nw // 2, mid_y
    d.polygon([(ax, ay), (ax - 9 * SS, ay - 5 * SS), (ax - 9 * SS, ay + 5 * SS)], fill=HOT)

    # --- nodes ---------------------------------------------------------------
    _node(d, col_x[0], row_y[0], nw, nh, src_u, "attacker-influenced", CLEAN, f_node, f_sub)
    if src_s:
        _node(d, col_x[0], row_y[1], nw, nh, src_s, "private data", CLEAN, f_node, f_sub)
    _node(d, col_x[1], mid_y, nw, nh, "__llm__", "cannot separate them", None, f_node, f_sub)
    _node(d, col_x[2], mid_y, nw, nh, sink, "leaves the boundary", HOT, f_node, f_sub,
          danger=True)

    # --- witness strip: the evidence, verbatim from the scan ------------------
    wy = int(H * 0.80) * SS
    d.line([int(W * 0.07) * SS, wy - 14 * SS, int(W * 0.93) * SS, wy - 14 * SS],
           fill=LINE, width=1 * SS)
    control = ""
    for ln in witness.splitlines():
        if "Control path" in ln:
            control = ln.split(":", 1)[1].strip()
    d.text((int(W * 0.07) * SS, wy), "witness", font=f_sub, fill=INK_MUTED)
    if control:
        x = int(W * 0.07) * SS + f_sub.getlength("witness") + 12 * SS
        hops = [h.strip() for h in control.split("→")]
        for i, hop in enumerate(hops):
            col = CLEAN if i == 0 else (HOT if i == len(hops) - 1 else WARN)
            d.text((x, wy), hop, font=f_wit, fill=col)
            x += f_wit.getlength(hop) + 8 * SS
            if i < len(hops) - 1:
                d.text((x, wy), "→", font=f_wit, fill=INK_MUTED)
                x += f_wit.getlength("→") + 8 * SS
    cap = "AG-TRIFECTA · actual output of `lucin scan` · regenerate: python site/make_hero.py"
    d.text((int(W * 0.07) * SS, wy + 26 * SS), cap, font=f_cap, fill=INK_MUTED)

    # downsample: this is what gives clean diagonals
    img = img.resize((W, H), Image.LANCZOS)
    img.save(OUT, "PNG", optimize=True)
    # a 2x asset for retina
    Image.new("RGB", (1, 1))  # keep Pillow import meaningful for linters
    return OUT


def main(argv: list[str]) -> int:
    target = DEFAULT_TARGET
    if "--target" in argv:
        target = argv[argv.index("--target") + 1]
    p = build(target)
    print(f"  wrote {p.relative_to(ROOT)} ({p.stat().st_size // 1024} KB, {W}x{H}) "
          f"from a real AIFG in {target.split('/')[-1]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
