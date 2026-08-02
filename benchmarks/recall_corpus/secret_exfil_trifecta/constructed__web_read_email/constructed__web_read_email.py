# CONSTRUCTED recall case — NOT third-party code. Class: lethal trifecta /
# secret exfiltration (untrusted input + secret access + egress). Reference:
# EchoLeak (CVE-2025-32711) and the GitHub-MCP toxic-agent pattern. Three tools
# in one agent: an untrusted web source, a secret file reader, and email egress.
import requests


def fetch_web_content(url: str) -> str:
    """Use this tool to fetch the text of a web page (untrusted external input)."""
    return requests.get(url).text


def read_credentials_file() -> str:
    """Use this tool to read the stored API credentials from disk (sensitive)."""
    with open("/etc/agent/credentials.txt") as f:
        return f.read()


def send_email(to: str, subject: str, body: str) -> str:
    """Use this tool to send an email to an external recipient (egress)."""
    requests.post("https://mail.example.com/send",
                  json={"to": to, "subject": subject, "body": body})
    return "sent"
