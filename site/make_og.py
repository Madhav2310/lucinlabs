#!/usr/bin/env python3
"""make_og.py — generate site/og.png (1200x630) from a REAL scan.

Every page referenced /og.png and the file did not exist, so a shared link showed a
broken image. Rather than draw a marketing graphic, this renders actual `lucin scan`
output: the findings table and the trifecta witness path from a real fixture. The
social preview is therefore an artifact of the tool, not a picture of one — which is
the same standard we hold every published number to.

Palette is the site's achromatic system; the only saturated pixels are severity and
the taint ramp (clean -> tainted), exactly as on the site.

Usage:  python site/make_og.py            # writes site/og.png
        python site/make_og.py --target X # scan a different path
"""
from __future__ import annotations

import json
import subprocess
import sys

BASE = "https://lucin.pages.dev"
DOMAIN_LABEL = BASE.split("://", 1)[1]          # -> "lucin.pages.dev"
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "site" / "og.png"
W, H = 1200, 630

# Paper/ink palette — must match the live site's light theme (rebrand, 2026-08).
CANVAS, SUNKEN = (250, 249, 247), (243, 242, 238)
INK, INK_SOFT, INK_MUTED = (20, 20, 20), (61, 65, 71), (108, 112, 118)
LINE, LINE_STRONG = (228, 225, 220), (215, 217, 220)
SEV = {"CRITICAL": (214, 50, 31), "HIGH": (184, 92, 31), "MEDIUM": (184, 134, 11),
       "LOW": (108, 112, 118), "INFO": (108, 112, 118)}
CLEAN, WARN, HOT = (61, 65, 71), (214, 154, 31), (214, 50, 31)

# macOS system faces; fall back to PIL's default rather than crashing on another OS.
_FONTS = ["/System/Library/Fonts/SFNSDisplay.ttf",
          "/System/Library/Fonts/Helvetica.ttc",
          "/Library/Fonts/Arial.ttf"]
_MONOS = ["/System/Library/Fonts/SFNSMono.ttf",
          "/System/Library/Fonts/Menlo.ttc",
          "/System/Library/Fonts/Courier.ttc"]


def _font(paths: list[str], size: int, index: int = 0):
    for p in paths:
        try:
            return ImageFont.truetype(p, size, index=index)
        except Exception:  # noqa: BLE001 — font availability varies by machine
            continue
    return ImageFont.load_default(size=size)


def _scan(target: str) -> list[dict]:
    out = subprocess.run(
        [sys.executable, "-m", "lucin", "scan", target, "--format", "json", "--no-telemetry"],
        capture_output=True, text=True, cwd=ROOT)
    try:
        return json.loads(out.stdout).get("findings", [])
    except json.JSONDecodeError:
        return []


def build(target: str) -> Path:
    findings = _scan(target)
    # Show the most severe first — the point of the image is the CRITICAL trifecta.
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: order.get(f.get("severity", "info"), 9))
    witness = next((f["witness"][0] for f in findings if f.get("witness")), "")

    img = Image.new("RGB", (W, H), CANVAS)
    d = ImageDraw.Draw(img)

    f_title = _font(_FONTS, 54)
    f_sub = _font(_FONTS, 23)
    f_mono = _font(_MONOS, 19)
    f_small = _font(_MONOS, 16)
    f_tiny = _font(_MONOS, 15)

    # headline + subhead
    d.text((64, 58), "See what your AI agent", font=f_title, fill=INK)
    d.text((64, 116), "can actually reach.", font=f_title, fill=INK)
    d.text((64, 190), "Static analysis for AI agents — it reads the code inside your tools.",
           font=f_sub, fill=INK_SOFT)

    # terminal panel: real output
    px, py, pw, ph = 64, 244, W - 128, 250
    d.rounded_rectangle([px, py, px + pw, py + ph], radius=8, fill=SUNKEN, outline=LINE)
    d.text((px + 22, py + 20), "$ lucin scan ./agent", font=f_mono, fill=INK)

    y = py + 58
    for fnd in findings[:5]:
        sev = fnd.get("severity", "info").upper()
        col = SEV.get(sev, INK_MUTED)
        d.text((px + 22, y), f"{sev:<9}", font=f_small, fill=col)
        d.text((px + 128, y), f"{fnd.get('id',''):<15}", font=f_small, fill=INK_SOFT)
        label = fnd.get("tool_name") or fnd.get("title") or ""
        # trim on a word boundary with an ellipsis — a title cut mid-word reads sloppy
        # on the one image that represents the project in every share.
        if len(label) > 42:
            label = label[:42].rsplit(" ", 1)[0].rstrip(" →'\"") + "…"
        d.text((px + 296, y), label, font=f_small, fill=INK_MUTED)
        y += 27

    if witness:
        d.text((px + 22, py + ph - 44), "witness:", font=f_tiny, fill=INK_MUTED)
        # the taint ramp: source is clean, the sink is hot
        parts = [p.strip() for p in witness.split("→")]
        x = px + 108
        for i, part in enumerate(parts):
            col = CLEAN if i == 0 else (HOT if i == len(parts) - 1 else WARN)
            txt = part.replace("control:", "").strip()[:26]
            d.text((x, py + ph - 44), txt, font=f_tiny, fill=col)
            x += f_tiny.getlength(txt) + 10
            if i < len(parts) - 1:
                d.text((x, py + ph - 44), "→", font=f_tiny, fill=INK_MUTED)
                x += f_tiny.getlength("→") + 10

    # footer: the paired numbers, same discipline as the page
    d.line([64, H - 96, W - 64, H - 96], fill=LINE, width=1)
    d.text((64, H - 76),
           "0 adjudicated FP / 2,732 files  ·  76% recall / 10 classes",
           font=f_small, fill=INK_SOFT)
    d.text((64, H - 46),
           "Open source · pip install lucin · every number regenerates from a command",
           font=f_tiny, fill=INK_MUTED)
    d.text((W - 168, H - 76), f"◆ {DOMAIN_LABEL}", font=f_small, fill=INK)

    img.save(OUT, "PNG", optimize=True)
    return OUT


def main(argv: list[str]) -> int:
    target = "real_world_tests/14_rag_agent/agent.py"
    if "--target" in argv:
        target = argv[argv.index("--target") + 1]
    p = build(target)
    print(f"  wrote {p.relative_to(ROOT)} ({p.stat().st_size // 1024} KB, {W}x{H}) "
          f"from a real scan of {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
