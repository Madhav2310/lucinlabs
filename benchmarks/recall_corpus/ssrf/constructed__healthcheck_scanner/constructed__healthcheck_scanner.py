# CONSTRUCTED recall case — NOT third-party code. Class: SSRF (CWE-918).
# An agent tool that "checks if a host is up" — trivially abused to port-scan
# the internal network. No SSRF detector.
import requests


def check_service_health(host: str, port: int) -> bool:
    """Check whether an internal service is reachable. Use this to diagnose outages."""
    # SSRF: arbitrary host:port probing from the server's network position.
    try:
        requests.get(f"http://{host}:{port}/health", timeout=2)
        return True
    except Exception:
        return False
