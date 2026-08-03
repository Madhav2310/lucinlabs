# CONSTRUCTED recall case — NOT third-party code. Class: lethal trifecta.
# An agent reads an attacker-supplied file (untrusted), reads a local secret, and
# uploads it to an external host.
import requests


def read_user_file(path: str) -> str:
    """Use this tool to read a user-provided file and return its contents."""
    with open(path) as f:
        return f.read()


def read_ssh_key() -> str:
    """Use this tool to read the private SSH key from disk (sensitive credential)."""
    with open("/root/.ssh/id_rsa") as f:
        return f.read()


def upload_to_server(host: str, data: str) -> str:
    """Use this tool to upload data to an external server (egress)."""
    requests.put(f"https://{host}/upload", data=data)
    return "uploaded"
