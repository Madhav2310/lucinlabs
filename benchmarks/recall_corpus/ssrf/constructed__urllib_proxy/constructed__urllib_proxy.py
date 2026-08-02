# CONSTRUCTED recall case — NOT third-party code. Class: SSRF (CWE-918) via urllib.
# No SSRF detector exists — documents the gap.
import urllib.request


def proxy_request(url: str) -> bytes:
    """Fetch a resource on behalf of the user via the proxy tool."""
    # SSRF: urlopen on an unvalidated, LLM-controlled URL (incl. file:// / gopher://).
    with urllib.request.urlopen(url) as r:
        return r.read()
