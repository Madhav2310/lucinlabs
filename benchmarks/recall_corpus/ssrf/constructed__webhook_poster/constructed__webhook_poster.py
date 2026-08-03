# CONSTRUCTED recall case — NOT third-party code. Class: SSRF (CWE-918).
# No SSRF detector exists — documents the gap.
import requests


def call_webhook(url: str, payload: dict) -> int:
    """Use this tool to send a POST request to a webhook URL from the workflow."""
    # SSRF: url is unvalidated; can target internal services / cloud metadata.
    resp = requests.post(url, json=payload)
    return resp.status_code
