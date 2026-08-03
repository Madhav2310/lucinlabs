import sys
from pathlib import Path
from build import _head, _chrome, _footer, SITE

def build_404():
    content = """
<main style="text-align: center; padding: 120px 24px;">
  <div style="font-family: var(--mono); font-size: 14px; color: var(--sev-crit); letter-spacing: 0.1em; margin-bottom: 24px;">404 &middot; NO SUCH PATH</div>
  <h1 style="font-size: 48px; margin-bottom: 24px;">That page doesn't exist.</h1>
  <p style="font-size: 18px; color: var(--ink-soft); max-width: 500px; margin: 0 auto 32px;">It may have moved, or the link may be wrong. Here are some useful places to go instead:</p>
  <div style="display: flex; gap: 16px; justify-content: center; flex-wrap: wrap;">
    <a href="/" style="text-decoration: none; padding: 10px 20px; background: var(--ink); color: var(--canvas); border-radius: 4px; font-weight: 500;">Home</a>
    <a href="/docs/" style="text-decoration: none; padding: 10px 20px; border: 1px solid var(--line); color: var(--ink); border-radius: 4px; font-weight: 500;">Quickstart</a>
    <a href="/rules/" style="text-decoration: none; padding: 10px 20px; border: 1px solid var(--line); color: var(--ink); border-radius: 4px; font-weight: 500;">Detection Rules</a>
  </div>
</main>
"""
    # Replace robots index with noindex for 404
    head = _head("Not found — Lucin", "That page doesn't exist.", "https://lucin.pages.dev/404.html", "Article")
    head = head.replace('<meta name="robots" content="index,follow,max-image-preview:large">', '<meta name="robots" content="noindex">')
    
    html = head + _chrome("") + content + _footer()
    
    dest = SITE / "404.html"
    dest.write_text(html, encoding="utf-8")
    print(f"  [ok] /404.html ({dest.stat().st_size // 1024} KB)")

if __name__ == "__main__":
    build_404()
