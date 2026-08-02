# CONSTRUCTED recall case — NOT third-party code. Class: path traversal (CWE-22).
# Naive prefix-join that does not prevent '../' escape. No path-traversal detector.
import os


def serve_file(filename: str) -> bytes:
    """Use this tool to return the bytes of a file from the agent's data directory."""
    # Traversal: os.path.join with '..' still escapes the base dir.
    full = os.path.join("./agent_data", filename)
    with open(full, "rb") as f:
        return f.read()
