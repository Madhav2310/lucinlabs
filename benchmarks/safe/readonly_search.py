# Expected: NO critical/high findings — read-only search agent
from langchain.tools import tool


@tool
def search_docs(query: str) -> str:
    """Search internal documentation for relevant articles."""
    return f"Results for: {query}"

@tool
def summarize_text(text: str) -> str:
    """Summarize a block of text."""
    return text[:200] + "..."
