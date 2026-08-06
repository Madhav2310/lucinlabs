"""Export figures.py SVGs as social-ready PNGs.

    python site/export_social.py                 # all figures
    python site/export_social.py hf-flow         # one
    python site/export_social.py --list          # show ids

Output: site/social/<fid>.png at 1600x900, 2x device scale.

No new dependencies: renders through headless Chrome, which is already on the
machine. `pip install cairosvg` is the cleaner alternative if you would rather
add the dependency, but this avoids it.

Every figure carries its own <figcaption>, which is included in the render, so
the exported image is self-contained and readable without the surrounding post.
"""

from __future__ import annotations

import argparse
import math
import pathlib
import shutil
import re
import subprocess
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).parent))

import figures  # noqa: E402

WIDTH = 1600
SCALE = 2
CONTENT_PCT = 0.88          # figure occupies this fraction of the canvas width
PAD_Y = 56                  # breathing room above the figure and below the caption
MIN_HEIGHT = 420
OUT = pathlib.Path(__file__).parent / "social"

CHROME_CANDIDATES = [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    "google-chrome",
    "chromium",
]


def find_chrome() -> str:
    for c in CHROME_CANDIDATES:
        if pathlib.Path(c).exists():
            return c
        found = shutil.which(c)
        if found:
            return found
    raise SystemExit(
        "export_social.py: no Chrome/Chromium found. Edit CHROME_CANDIDATES, "
        "or use cairosvg instead."
    )


def canvas_height(svg: str, caption_chars: int) -> int:
    """Height that fits the figure at its own aspect ratio, plus its caption.

    Forcing every figure into 16:9 left most of them floating in dead space,
    because the source viewBoxes are wide and short (640x176 is typical).
    """
    m = re.search(r'viewBox="0 0 ([\d.]+) ([\d.]+)"', svg)
    if not m:
        return 900
    vb_w, vb_h = float(m.group(1)), float(m.group(2))
    svg_h = (WIDTH * CONTENT_PCT) * (vb_h / vb_w)
    # caption wraps at roughly 130 chars per line at this width, 27px line box
    cap_lines = max(1, math.ceil(caption_chars / 130))
    cap_h = 20 + cap_lines * 27
    return max(MIN_HEIGHT, round(svg_h + cap_h + PAD_Y * 2))


def page(fid: str) -> tuple[str, int]:
    """Wrap one figure in a page sized to the figure itself."""
    svg = figures.render(fid)
    cap = re.search(r"<figcaption>(.*?)</figcaption>", svg, re.S)
    cap_chars = len(re.sub(r"<[^>]+>", "", cap.group(1))) if cap else 0
    height = canvas_height(svg, cap_chars)
    html = f"""<!doctype html><meta charset="utf-8">
<style>
  html, body {{
    margin: 0; padding: 0;
    width: {WIDTH}px; height: {height}px;
    background: #ffffff;
    display: flex; align-items: center; justify-content: center;
  }}
  .wrap {{ width: {int(CONTENT_PCT * 100)}%; }}
  figure.fig {{ margin: 0; }}
  figure.fig svg {{ width: 100%; height: auto; display: block; }}
  figure.fig figcaption {{ margin-top: 20px; font-size: 15px; line-height: 1.5; }}
</style>
{figures.CSS}
<body><div class="wrap">{svg}</div></body>"""
    return html, height


def export(fid: str, chrome: str) -> pathlib.Path:
    OUT.mkdir(exist_ok=True)
    png = OUT / f"{fid}.png"
    html, height = page(fid)
    with tempfile.NamedTemporaryFile("w", suffix=".html", delete=False, encoding="utf-8") as fh:
        fh.write(html)
        tmp = fh.name
    try:
        subprocess.run(
            [
                chrome,
                "--headless",
                "--disable-gpu",
                "--hide-scrollbars",
                "--no-sandbox",
                f"--screenshot={png}",
                f"--window-size={WIDTH},{height}",
                f"--force-device-scale-factor={SCALE}",
                f"file://{tmp}",
            ],
            check=True,
            capture_output=True,
            timeout=60,
        )
    finally:
        pathlib.Path(tmp).unlink(missing_ok=True)
    if not png.exists() or png.stat().st_size < 2000:
        raise SystemExit(f"export_social.py: {fid} produced no usable PNG")
    return png


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("ids", nargs="*", help="figure ids (default: all)")
    ap.add_argument("--list", action="store_true", help="list ids and exit")
    args = ap.parse_args()

    if args.list:
        for fid in sorted(figures.FIGURES):
            print(fid)
        return

    errs = figures.check()
    if errs:
        raise SystemExit("figures.check() failed, fix these first:\n  " + "\n  ".join(errs))

    chrome = find_chrome()
    ids = args.ids or sorted(figures.FIGURES)
    for fid in ids:
        png = export(fid, chrome)
        kb = png.stat().st_size // 1024
        print(f"{kb:>5} KB  {png}")


if __name__ == "__main__":
    main()
