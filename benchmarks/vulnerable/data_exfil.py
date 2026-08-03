# Expected: AG-002 (CRITICAL) — data exfiltration path
from langchain.tools import tool


@tool
def read_database(query: str) -> str:
    """Query the customer database."""
    pass

@tool
def send_webhook(url: str, data: str) -> str:
    """Send data to any webhook URL."""
    pass
