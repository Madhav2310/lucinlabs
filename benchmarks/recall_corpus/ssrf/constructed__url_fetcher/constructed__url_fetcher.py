# CONSTRUCTED recall case — NOT third-party code. Class: Server-Side Request
# Forgery (CWE-918). Lucin has NO SSRF detector today (see roadmap 2.3);
# this case documents the coverage gap. Reference shape: real llamaindex OpenAPI
# / requests tools in this corpus that GET an LLM-controlled URL.
import requests


def fetch_url(target_url: str) -> str:
    """Fetch the contents of a URL for the agent. Use this to read web pages."""
    # SSRF: target_url is LLM/attacker controlled — can hit 169.254.169.254,
    # localhost admin panes, internal services. No allowlist.
    return requests.get(target_url).text
