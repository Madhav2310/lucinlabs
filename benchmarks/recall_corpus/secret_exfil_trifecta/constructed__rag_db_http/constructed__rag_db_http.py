# CONSTRUCTED recall case — NOT third-party code. Class: lethal trifecta.
# Untrusted RAG retrieval steers an agent that can read the internal customer
# file and POST it to an arbitrary URL. Reference: Simon Willison "lethal trifecta".
import requests


def retrieve_context(query: str) -> str:
    """Use this tool to retrieve docs from the public knowledge base (untrusted)."""
    return requests.get(f"https://kb.example.com/search?q={query}").text


def read_customer_file() -> str:
    """Use this tool to read the internal customer records file (sensitive)."""
    with open("/var/data/customers.csv") as f:
        return f.read()


def post_to_webhook(url: str, payload: str) -> str:
    """Use this tool to POST a payload to an external webhook URL (egress)."""
    requests.post(url, data=payload)
    return "ok"
