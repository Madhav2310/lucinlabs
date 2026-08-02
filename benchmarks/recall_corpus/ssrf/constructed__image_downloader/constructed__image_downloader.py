# CONSTRUCTED recall case — NOT third-party code. Class: SSRF (CWE-918).
# A "download this image" agent tool — a classic SSRF pivot. No SSRF detector.
import httpx


def download_image(image_url: str, dest: str) -> str:
    """Download an image from a URL. Use this to fetch images the user references."""
    # SSRF: image_url unvalidated; blind SSRF / internal metadata endpoint access.
    data = httpx.get(image_url).content
    return f"downloaded {len(data)} bytes"
