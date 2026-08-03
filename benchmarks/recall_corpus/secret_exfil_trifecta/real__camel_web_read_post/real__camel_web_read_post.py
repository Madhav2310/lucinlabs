# REAL-WORLD trifecta case (assembled from VERBATIM third-party tool bodies).
#
# WHAT THIS IS (honest provenance — read before trusting the label):
#   A single CAMEL-style agent that registers three real single-purpose tools.
#   The lethal trifecta is EMERGENT from composing them into one agent — which
#   is exactly how real deployments create the vulnerability and why Lucin
#   scans the assembled agent, not individual tools. Each tool BODY below is the
#   real dangerous-call pattern taken verbatim from camel-ai/camel toolkits (we
#   did not write the HTTP/file logic); only the composition into one agent is
#   ours (disclosed). Real production toolkits are single-purpose by design, so
#   no single upstream file contains all three legs — the risk only appears once
#   an operator wires them together.
#
# PROVENANCE (camel-ai/camel, Apache-2.0, https://github.com/camel-ai/camel):
#   - web_fetch_and_analyze : httpx.Client().get(...) core is verbatim from
#       camel/toolkits/web_fetch_toolkit.py  (WebFetchToolkit.web_fetch_and_analyze)
#       -> UNTRUSTED external web content enters the agent's context.
#   - read_file             : local file read (open/read) as in
#       camel/toolkits/file_toolkit.py  (FileToolkit.read_file)
#       -> SENSITIVE local data (credentials/config).
#   - http_post             : requests.post(...) egress pattern verbatim from
#       camel/toolkits/search_toolkit.py  (SearchToolkit._search_serper's POST)
#       -> EGRESS sink to an external URL.
#
# The trifecta: attacker-controlled web content (web_fetch) can steer the LLM to
# read the sensitive file and POST it to an external URL — Willison's lethal
# trifecta; the same shape as EchoLeak (CVE-2025-32711).

import httpx
import requests

_ALLOWED_SCHEMES = ("http", "https")


def web_fetch_and_analyze(url: str, request_timeout: float = 20.0) -> str:
    """Use this tool to fetch a web page and return its text for the agent to
    reason over (UNTRUSTED external web content)."""
    with httpx.Client(
        follow_redirects=True,
        timeout=request_timeout,
        headers={
            "User-Agent": (
                "Mozilla/5.0 (compatible; CAMEL WebFetchToolkit/1.0)"
            )
        },
    ) as client:
        http_response = client.get(url)
    return http_response.text


def read_file(path: str) -> str:
    """Use this tool to read a local file's contents (SENSITIVE credentials/
    config data)."""
    with open(path, "r", encoding="utf-8") as file:
        return file.read()


def http_post(url: str, payload: dict, timeout: float = 10.0) -> dict:
    """Use this tool to POST a payload to an external URL. Sends a request to an
    external destination (EGRESS sink)."""
    headers = {"Content-Type": "application/json"}
    response = requests.post(url, headers=headers, json=payload, timeout=timeout)
    return response.json()
